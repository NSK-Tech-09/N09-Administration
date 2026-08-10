import { createHash, randomBytes, randomUUID } from "node:crypto";
import { evaluateAccessRequestAsync } from "./api.mjs";
import { createAuditEvent } from "./audit.mjs";

export const APPLICATION_LOGIN_CODE_LIFETIME_MS = 90_000;

export function authorizationCodeHash(code) {
  return createHash("sha256").update(String(code), "utf8").digest("hex");
}

export function verifierChallenge(verifier) {
  return createHash("sha256").update(String(verifier), "utf8").digest("base64url");
}

export function validateAuthorizationRequest(query) {
  const applicationId = query.get("client_id");
  const redirectUri = query.get("redirect_uri");
  const state = query.get("state");
  const codeChallenge = query.get("code_challenge");
  if (!applicationId || !redirectUri || !state || !codeChallenge) throw new Error("invalid_authorization_request");
  if (!/^[a-z0-9][a-z0-9-]{2,99}$/.test(applicationId)) throw new Error("invalid_authorization_request");
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(state) || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
    throw new Error("invalid_authorization_request");
  }
  let redirect;
  try { redirect = new URL(redirectUri); } catch { throw new Error("invalid_authorization_request"); }
  if (redirect.protocol !== "https:" || redirect.username || redirect.password || redirect.hash) {
    throw new Error("invalid_authorization_request");
  }
  return { applicationId, redirectUri: redirect.toString(), state, codeChallenge };
}

export async function issueApplicationLoginCode({ repository, session, request, now = Date.now() }) {
  if (session?.status !== "authenticated" || !session.identityId) throw new Error("authentication_required");
  const redirectAllowed = await repository.isApplicationRedirectUriAllowed(request.applicationId, request.redirectUri);
  if (!redirectAllowed) throw new Error("redirect_uri_not_allowed");
  const policy = await repository.getApplicationLoginPolicy(request.applicationId);
  if (!policy || policy.status !== "active" || typeof policy.requiredPermission !== "string" || !policy.requiredPermission) {
    throw new Error("application_login_not_configured");
  }
  const decision = await evaluateAccessRequestAsync({
    repository,
    principal: { applicationId: request.applicationId, audience: request.applicationId },
    payload: {
      identity_id: session.identityId,
      application_id: request.applicationId,
      required_permission: policy.requiredPermission,
      satisfied_conditions: [],
    },
  });
  if (decision.status !== 200 || decision.body.allowed !== true) throw new Error("application_access_denied");
  const code = randomBytes(32).toString("base64url");
  const record = {
    codeHash: authorizationCodeHash(code), identityId: session.identityId,
    applicationId: request.applicationId, redirectUri: request.redirectUri,
    codeChallenge: request.codeChallenge, issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + APPLICATION_LOGIN_CODE_LIFETIME_MS).toISOString(),
  };
  await repository.saveApplicationAuthorizationCode(record, createAuditEvent({
    action: "application_login.code_issued", result: "success", source: "application-login",
    correlationId: randomUUID(), subjectId: session.identityId, applicationId: request.applicationId,
    newValue: { expires_at: record.expiresAt },
  }));
  return { code, record };
}

export async function exchangeApplicationLoginCode({ repository, principal, payload, now = Date.now() }) {
  if (!principal || principal.applicationId !== payload?.client_id || principal.audience !== principal.applicationId) {
    throw new Error("invalid_technical_client");
  }
  if (![payload?.code, payload?.redirect_uri, payload?.code_verifier].every((value) => typeof value === "string" && value)) {
    throw new Error("invalid_token_request");
  }
  const record = await repository.consumeApplicationAuthorizationCode({
    codeHash: authorizationCodeHash(payload.code), applicationId: principal.applicationId,
    redirectUri: payload.redirect_uri, codeChallenge: verifierChallenge(payload.code_verifier),
    now: new Date(now),
  }, createAuditEvent({
    action: "application_login.code_consumed", result: "success", source: "application-login-token",
    correlationId: randomUUID(), applicationId: principal.applicationId,
  }));
  if (!record) throw new Error("invalid_or_consumed_code");
  const identity = await repository.getIdentity(record.identityId);
  if (!identity || identity.status !== "active") throw new Error("identity_not_active");
  return {
    identity_id: identity.identityId,
    display_name: identity.displayName,
    email: identity.email,
    application_id: principal.applicationId,
  };
}
