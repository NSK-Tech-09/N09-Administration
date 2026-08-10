import { createHash, randomUUID } from "node:crypto";

export const LINK_REQUEST_TTL_MS = 15 * 60 * 1000;

function optionalHint(value, maxLength) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim();
  return normalized ? normalized.slice(0, maxLength) : null;
}

export function assertExternalPrincipal({ issuer, subject, providerKey }) {
  let parsed;
  try { parsed = new URL(issuer); } catch { throw new Error("OIDC issuer must be an absolute HTTPS URL"); }
  if (parsed.protocol !== "https:" || !parsed.hostname) throw new Error("OIDC issuer must be an absolute HTTPS URL");
  if (typeof subject !== "string" || !subject.trim()) throw new Error("OIDC subject must not be empty");
  if (typeof providerKey !== "string" || !providerKey.trim()) throw new Error("provider key must not be empty");
}

export function externalPrincipalKey(issuer, subject) {
  return createHash("sha256").update(`${issuer}\n${subject}`, "utf8").digest("hex");
}

export function createLinkRequest({
  issuer,
  subject,
  providerKey,
  emailHint = null,
  displayNameHint = null,
  now = new Date(),
  ttlMs = LINK_REQUEST_TTL_MS,
  requestId = randomUUID(),
}) {
  assertExternalPrincipal({ issuer, subject, providerKey });
  if (!(now instanceof Date) || Number.isNaN(now.valueOf())) throw new Error("request date must be valid");
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error("link request TTL must be positive");
  return Object.freeze({
    requestId,
    issuer,
    subject: subject.trim(),
    providerKey: providerKey.trim(),
    emailHint: optionalHint(emailHint, 320)?.toLowerCase() ?? null,
    displayNameHint: optionalHint(displayNameHint, 255),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.valueOf() + ttlMs).toISOString(),
    status: "pending",
    targetIdentityId: null,
    decidedBy: null,
    decisionJustification: "",
  });
}

export function isActiveLinkRequest(request, now = new Date()) {
  return request?.status === "pending" && new Date(request.expiresAt) > now;
}
