import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

export const APPLICATION_SESSION_SECRET_BYTES = 32;
export const APPLICATION_SESSION_MIN_IDLE_MS = 5 * 60_000;
export const APPLICATION_SESSION_MAX_ABSOLUTE_MS = 24 * 60 * 60_000;

function iso(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.valueOf())) throw new Error("invalid_session_date");
  return date.toISOString();
}

function requiredIdentifier(value, name, maximum = 100) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error(`invalid_${name}`);
  }
  return value.trim();
}

function validDuration(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`invalid_${name}`);
  return value;
}

export function applicationSessionSecretHash(secret) {
  if (typeof secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    throw new Error("invalid_session_secret");
  }
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

export function assertNewApplicationSessionRecord(record) {
  const issuedAt = new Date(record.issuedAt);
  const lastSeenAt = new Date(record.lastSeenAt);
  const idleExpiresAt = new Date(record.idleExpiresAt);
  const absoluteExpiresAt = new Date(record.absoluteExpiresAt);
  const authenticatedAt = new Date(record.authenticatedAt);
  if (record.version !== 1 || record.revokedAt || record.revokedByIdentityId || record.revocationReason ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(record.sessionId) ||
      !/^[0-9a-f]{64}$/.test(record.secretHash) ||
      !Number.isSafeInteger(record.idleTtlMs) || record.idleTtlMs <= 0 ||
      typeof record.contextLabel !== "string" || record.contextLabel.length > 255 ||
      ![issuedAt, lastSeenAt, idleExpiresAt, absoluteExpiresAt, authenticatedAt]
        .every((date) => Number.isFinite(date.valueOf())) ||
      authenticatedAt > issuedAt || issuedAt > lastSeenAt || lastSeenAt >= idleExpiresAt ||
      idleExpiresAt > absoluteExpiresAt) {
    throw new Error("invalid new application session record");
  }
}

export function assertApplicationSessionImmutableContext(previous, next) {
  for (const field of [
    "sessionId", "secretHash", "identityId", "applicationId", "issuedAt",
    "absoluteExpiresAt", "authenticatedAt", "idleTtlMs", "contextLabel",
  ]) {
    if (previous[field] !== next[field]) throw new Error(`application session ${field} is immutable`);
  }
}

export function assertApplicationSessionActivityWindow(record) {
  const activity = new Date(record.lastSeenAt);
  const idleExpiry = new Date(record.idleExpiresAt);
  const absoluteExpiry = new Date(record.absoluteExpiresAt);
  if (![activity, idleExpiry, absoluteExpiry].every((date) => Number.isFinite(date.valueOf())) ||
      activity >= idleExpiry || idleExpiry > absoluteExpiry) {
    throw new Error("invalid application session activity progression");
  }
}

export function assertApplicationSessionActivityProgress(previous, next) {
  const previousActivity = new Date(previous.lastSeenAt);
  const nextActivity = new Date(next.lastSeenAt);
  assertApplicationSessionActivityWindow(next);
  if (!Number.isFinite(previousActivity.valueOf()) || !Number.isFinite(nextActivity.valueOf()) ||
      nextActivity <= previousActivity || previous.absoluteExpiresAt !== next.absoluteExpiresAt) {
    throw new Error("invalid application session activity progression");
  }
}

export function assertApplicationSessionAudit(record, auditEvent, expectedAction) {
  if (auditEvent.action !== expectedAction || auditEvent.subject_id !== record.identityId ||
      auditEvent.application_id !== record.applicationId) {
    throw new Error("audit context must match application session");
  }
  const serialized = JSON.stringify(auditEvent);
  if (serialized.includes(record.sessionId) || serialized.includes(record.secretHash)) {
    throw new Error("audit must not contain application session identifiers or secret hashes");
  }
  if (expectedAction === "application_session.revoked" &&
      auditEvent.actor_id !== record.revokedByIdentityId) {
    throw new Error("audit actor must match application session revoker");
  }
}

export function createApplicationSession({
  identityId,
  applicationId,
  idleTtlMs,
  absoluteTtlMs,
  contextLabel = "",
  authenticatedAt = new Date(),
  now = new Date(),
  randomBytesImpl = randomBytes,
  randomUuidImpl = randomUUID,
}) {
  const normalizedIdentityId = requiredIdentifier(identityId, "identity_id", 36);
  const normalizedApplicationId = requiredIdentifier(applicationId, "application_id");
  const idle = validDuration(idleTtlMs, "idle_ttl");
  const absolute = validDuration(absoluteTtlMs, "absolute_ttl");
  if (idle < APPLICATION_SESSION_MIN_IDLE_MS || idle > absolute || absolute > APPLICATION_SESSION_MAX_ABSOLUTE_MS) {
    throw new Error("invalid_session_lifetime");
  }
  if (typeof contextLabel !== "string" || contextLabel.length > 255) throw new Error("invalid_session_context");

  const issuedAt = new Date(now);
  const authenticationTime = new Date(authenticatedAt);
  if (!Number.isFinite(issuedAt.valueOf()) || !Number.isFinite(authenticationTime.valueOf()) ||
      authenticationTime > issuedAt) throw new Error("invalid_session_date");

  const sessionId = randomUuidImpl();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)) {
    throw new Error("invalid_session_id");
  }
  const secretBuffer = randomBytesImpl(APPLICATION_SESSION_SECRET_BYTES);
  if (!Buffer.isBuffer(secretBuffer) || secretBuffer.length !== APPLICATION_SESSION_SECRET_BYTES) {
    throw new Error("invalid_session_randomness");
  }
  const secret = secretBuffer.toString("base64url");

  return Object.freeze({
    credential: Object.freeze({ sessionId, secret }),
    record: Object.freeze({
      sessionId,
      secretHash: applicationSessionSecretHash(secret),
      identityId: normalizedIdentityId,
      applicationId: normalizedApplicationId,
      issuedAt: issuedAt.toISOString(),
      lastSeenAt: issuedAt.toISOString(),
      idleExpiresAt: new Date(issuedAt.valueOf() + idle).toISOString(),
      absoluteExpiresAt: new Date(issuedAt.valueOf() + absolute).toISOString(),
      authenticatedAt: authenticationTime.toISOString(),
      idleTtlMs: idle,
      contextLabel: contextLabel.trim(),
      revokedAt: null,
      revokedByIdentityId: null,
      revocationReason: "",
      version: 1,
    }),
  });
}

function safeHashMatch(left, right) {
  const leftBuffer = Buffer.from(String(left), "hex");
  const rightBuffer = Buffer.from(String(right), "hex");
  return leftBuffer.length === 32 && rightBuffer.length === 32 && timingSafeEqual(leftBuffer, rightBuffer);
}

export function assessApplicationSession(record, {
  sessionId,
  secret,
  identityId,
  applicationId,
  now = new Date(),
}) {
  if (!record) return Object.freeze({ allowed: false, reasonCode: "session_unknown" });
  const currentTime = new Date(now);
  if (!Number.isFinite(currentTime.valueOf())) throw new Error("invalid_session_date");
  if (record.sessionId !== sessionId || record.identityId !== identityId || record.applicationId !== applicationId) {
    return Object.freeze({ allowed: false, reasonCode: "session_context_mismatch" });
  }
  let suppliedHash;
  try { suppliedHash = applicationSessionSecretHash(secret); }
  catch { return Object.freeze({ allowed: false, reasonCode: "session_secret_invalid" }); }
  if (!safeHashMatch(record.secretHash, suppliedHash)) {
    return Object.freeze({ allowed: false, reasonCode: "session_secret_invalid" });
  }
  if (record.revokedAt) return Object.freeze({ allowed: false, reasonCode: "session_revoked" });
  const absoluteExpiry = new Date(record.absoluteExpiresAt);
  const idleExpiry = new Date(record.idleExpiresAt);
  if (!Number.isFinite(absoluteExpiry.valueOf()) || !Number.isFinite(idleExpiry.valueOf()) ||
      idleExpiry > absoluteExpiry) {
    return Object.freeze({ allowed: false, reasonCode: "session_record_invalid" });
  }
  if (absoluteExpiry <= currentTime) {
    return Object.freeze({ allowed: false, reasonCode: "session_absolute_expired" });
  }
  if (idleExpiry <= currentTime) {
    return Object.freeze({ allowed: false, reasonCode: "session_idle_expired" });
  }
  return Object.freeze({ allowed: true, reasonCode: "session_active" });
}

export function touchApplicationSession(record, { now = new Date() } = {}) {
  const currentTime = new Date(now);
  const absoluteExpiry = new Date(record.absoluteExpiresAt);
  if (!Number.isFinite(currentTime.valueOf()) || !Number.isFinite(absoluteExpiry.valueOf())) {
    throw new Error("invalid_session_date");
  }
  if (currentTime <= new Date(record.lastSeenAt)) throw new Error("invalid_session_activity_time");
  if (record.revokedAt || currentTime >= absoluteExpiry || currentTime >= new Date(record.idleExpiresAt)) {
    throw new Error("inactive_session_cannot_be_touched");
  }
  const nextIdleExpiry = new Date(Math.min(
    currentTime.valueOf() + validDuration(record.idleTtlMs, "idle_ttl"),
    absoluteExpiry.valueOf(),
  ));
  return Object.freeze({
    ...record,
    lastSeenAt: currentTime.toISOString(),
    idleExpiresAt: nextIdleExpiry.toISOString(),
    version: record.version + 1,
  });
}

export function revokeApplicationSession(record, {
  revokedByIdentityId = null,
  reason,
  now = new Date(),
}) {
  if (record.revokedAt) return record;
  const normalizedReason = typeof reason === "string" ? reason.trim() : "";
  if (normalizedReason.length < 3 || normalizedReason.length > 500) throw new Error("invalid_revocation_reason");
  if (revokedByIdentityId !== null) requiredIdentifier(revokedByIdentityId, "revoker_identity_id", 36);
  return Object.freeze({
    ...record,
    revokedAt: iso(now),
    revokedByIdentityId,
    revocationReason: normalizedReason,
    version: record.version + 1,
  });
}

export function createApplicationSessionAuditEvent({
  record,
  action,
  actorId = null,
  justification = "",
  correlationId = randomUUID(),
  occurredAt = new Date(),
}) {
  if (!["application_session.created", "application_session.revoked"].includes(action)) {
    throw new Error("invalid_application_session_audit_action");
  }
  const revoked = action === "application_session.revoked";
  if (revoked && (!record.revokedAt || !record.revocationReason)) {
    throw new Error("invalid_application_session_audit_state");
  }
  return createAuditEvent({
    action,
    result: "success",
    source: "application-session-registry",
    correlationId,
    actorId,
    subjectId: record.identityId,
    applicationId: record.applicationId,
    cause: revoked ? "explicit_revocation" : "authenticated_session_opened",
    previousValue: revoked ? { state: "active", version: record.version - 1 } : null,
    newValue: {
      state: revoked ? "revoked" : "active",
      version: record.version,
      idle_expires_at: record.idleExpiresAt,
      absolute_expires_at: record.absoluteExpiresAt,
    },
    justification: revoked ? (justification || record.revocationReason) : justification,
    occurredAt,
  });
}
