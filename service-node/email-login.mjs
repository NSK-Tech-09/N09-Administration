import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

export const EMAIL_LOGIN_PROVIDER = "email";
export const EMAIL_LOGIN_ISSUER = "https://nsktech.fr/auth/email";
export const EMAIL_LOGIN_TTL_MS = 10 * 60_000;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export class EmailLoginError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "EmailLoginError";
    this.code = code;
    this.status = status;
  }
}

export function normalizeLoginEmail(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized || normalized.length > 320 || !EMAIL.test(normalized)) {
    throw new EmailLoginError("invalid_email");
  }
  return normalized;
}

export function hashEmailLoginToken(value) {
  if (!TOKEN.test(String(value ?? ""))) throw new EmailLoginError("invalid_or_consumed_email_login");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function exactHttpsOrigin(value) {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" ||
      parsed.search || parsed.hash) throw new Error("N09_PUBLIC_ORIGIN must be an exact HTTPS origin");
  return parsed.origin;
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`missing email login setting: ${name}`);
  return value.trim();
}

export function emailLoginConfigFromEnvironment(environment = process.env) {
  if (environment.N09_EMAIL_LOGIN_ENABLED !== "true") return Object.freeze({ enabled: false });
  const provider = required(environment, "N09_EMAIL_LOGIN_DELIVERY_PROVIDER");
  if (provider !== "brevo") throw new Error("N09_EMAIL_LOGIN_DELIVERY_PROVIDER must be brevo");
  const senderEmail = normalizeLoginEmail(required(environment, "N09_EMAIL_LOGIN_SENDER_EMAIL"));
  const senderName = required(environment, "N09_EMAIL_LOGIN_SENDER_NAME");
  if (senderName.length > 120) throw new Error("N09_EMAIL_LOGIN_SENDER_NAME is too long");
  const apiKey = required(environment, "N09_EMAIL_LOGIN_BREVO_API_KEY");
  if (apiKey.length < 20) throw new Error("N09_EMAIL_LOGIN_BREVO_API_KEY is invalid");
  return Object.freeze({
    enabled: true,
    provider,
    publicOrigin: exactHttpsOrigin(required(environment, "N09_PUBLIC_ORIGIN")),
    senderEmail,
    senderName,
    apiKey,
  });
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

export function createEmailLoginDelivery(config, { fetchImpl = fetch } = {}) {
  if (!config?.enabled) return Object.freeze({ enabled: false });
  if (typeof fetchImpl !== "function") throw new Error("email login fetch implementation is required");
  return Object.freeze({
    enabled: true,
    async send({ to, displayName, loginUrl }) {
      const safeName = escapeHtml(displayName || "");
      const safeUrl = escapeHtml(loginUrl);
      const response = await fetchImpl("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { accept: "application/json", "api-key": config.apiKey, "content-type": "application/json" },
        body: JSON.stringify({
          sender: { email: config.senderEmail, name: config.senderName },
          to: [{ email: to, name: displayName }],
          subject: "Ton lien de connexion NSK Tech 09",
          textContent: `Bonjour ${displayName || ""},\n\nOuvre ce lien pour te connecter à NSK Tech 09 :\n${loginUrl}\n\nCe lien est valable 10 minutes et ne peut être utilisé qu’une fois. Si tu n’es pas à l’origine de cette demande, ignore ce message.`,
          htmlContent: `<p>Bonjour ${safeName},</p><p><a href="${safeUrl}">Se connecter à NSK Tech 09</a></p><p>Ce lien est valable 10 minutes et ne peut être utilisé qu’une fois.</p><p>Si tu n’es pas à l’origine de cette demande, ignore ce message.</p>`,
          tags: ["n09-email-login"],
        }),
      });
      if (!response.ok) throw new Error("email_login_delivery_failed");
    },
  });
}

export async function requestEmailLogin({
  repository,
  email,
  returnTo,
  delivery,
  publicOrigin,
  now = new Date(),
  tokenFactory = () => randomBytes(32).toString("base64url"),
}) {
  const normalizedEmail = normalizeLoginEmail(email);
  if (!repository || typeof repository.findIdentityByEmail !== "function" ||
      typeof repository.saveEmailLoginToken !== "function" ||
      typeof repository.failEmailLoginToken !== "function") throw new Error("email login repository is incomplete");
  if (!delivery?.enabled || typeof delivery.send !== "function") throw new EmailLoginError("email_login_unavailable", 503);
  if (typeof returnTo !== "string" || !returnTo.startsWith("/") || /[\r\n]/.test(returnTo)) {
    throw new EmailLoginError("invalid_return_to");
  }
  const identity = await repository.findIdentityByEmail(normalizedEmail);
  if (!identity || identity.status !== "active") return Object.freeze({ accepted: true, delivered: false });

  const rawToken = tokenFactory();
  const tokenHash = hashEmailLoginToken(rawToken);
  const requestedAt = new Date(now);
  const record = Object.freeze({
    tokenId: randomUUID(), tokenHash, identityId: identity.identityId, returnTo,
    status: "issued", requestedAt: requestedAt.toISOString(),
    expiresAt: new Date(requestedAt.valueOf() + EMAIL_LOGIN_TTL_MS).toISOString(),
    consumedAt: null, invalidatedAt: null,
  });
  await repository.saveEmailLoginToken(record, createAuditEvent({
    action: "email_login.requested", result: "pending", source: "email-login",
    correlationId: randomUUID(), subjectId: identity.identityId,
    newValue: { email_login_id: record.tokenId, status: record.status, expires_at: record.expiresAt },
  }));
  try {
    await delivery.send({
      to: identity.email,
      displayName: identity.displayName,
      loginUrl: `${publicOrigin}/auth/email/confirm?token=${encodeURIComponent(rawToken)}`,
    });
  } catch {
    await repository.failEmailLoginToken({
      tokenHash, now: new Date(),
      auditEvent: createAuditEvent({
        action: "email_login.delivery_failed", result: "failure", source: "email-login",
        correlationId: randomUUID(), subjectId: identity.identityId,
        previousValue: { email_login_id: record.tokenId, status: "issued" },
        newValue: { email_login_id: record.tokenId, status: "delivery_failed" },
      }),
    });
    throw new EmailLoginError("email_login_delivery_failed", 503);
  }
  return Object.freeze({ accepted: true, delivered: true });
}

export async function inspectEmailLogin({ repository, token, now = new Date() }) {
  const tokenHash = hashEmailLoginToken(token);
  const pending = await repository.getEmailLoginToken(tokenHash);
  if (!pending || pending.status !== "issued" || new Date(pending.expiresAt) <= now) {
    throw new EmailLoginError("invalid_or_consumed_email_login");
  }
  return Object.freeze({ expiresAt: pending.expiresAt });
}

export async function consumeEmailLogin({ repository, token, now = new Date() }) {
  const tokenHash = hashEmailLoginToken(token);
  const pending = await repository.getEmailLoginToken(tokenHash);
  if (!pending || pending.status !== "issued" || new Date(pending.expiresAt) <= now) {
    throw new EmailLoginError("invalid_or_consumed_email_login");
  }
  const consumedAt = new Date(now).toISOString();
  let consumed;
  try {
    consumed = await repository.consumeEmailLoginToken({
      tokenHash, now,
      auditEvent: createAuditEvent({
        action: "email_login.consumed", result: "success", source: "email-login",
        correlationId: randomUUID(), subjectId: pending.identityId,
        previousValue: { email_login_id: pending.tokenId, status: "issued" },
        newValue: { email_login_id: pending.tokenId, status: "consumed", consumed_at: consumedAt },
      }),
    });
  } catch (error) {
    if (error?.message === "invalid_or_consumed_email_login") {
      throw new EmailLoginError("invalid_or_consumed_email_login");
    }
    throw error;
  }
  const identity = await repository.getIdentity(consumed.identityId);
  if (!identity || identity.status !== "active") throw new EmailLoginError("identity_not_active", 403);
  return Object.freeze({ identity, returnTo: consumed.returnTo });
}
