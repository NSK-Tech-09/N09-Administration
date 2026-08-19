import {
  createApplicationSessionAuditEvent,
  revokeApplicationSession,
} from "./application-session.mjs";
import { applicationDisplayName } from "./application-display-name.mjs";

export class PersonalSessionError extends Error {
  constructor(code, status = 409) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function stateOf(record, now) {
  if (record.revokedAt) return "revoked";
  if (new Date(record.absoluteExpiresAt) <= now || new Date(record.idleExpiresAt) <= now) return "expired";
  return "active";
}

function closure(record, identityId, reason, now) {
  const revoked = revokeApplicationSession(record, {
    revokedByIdentityId: identityId,
    reason,
    now,
  });
  return Object.freeze({
    record: revoked,
    expectedVersion: record.version,
    auditEvent: createApplicationSessionAuditEvent({
      record: revoked,
      action: "application_session.revoked",
      actorId: identityId,
      justification: reason,
      occurredAt: now,
    }),
  });
}

export function createPersonalSessionManagement({ repository, now = () => new Date() } = {}) {
  if (!repository || typeof repository.listApplicationSessions !== "function" ||
      typeof repository.revokeApplicationSession !== "function" ||
      typeof repository.revokeApplicationSessions !== "function") {
    throw new Error("personal session repository is required");
  }

  async function ownRecords(identityId) {
    if (typeof identityId !== "string" || !identityId) throw new PersonalSessionError("identity_required", 401);
    return repository.listApplicationSessions(identityId);
  }

  async function listOwn({ identityId, currentSessionId }) {
    const observedAt = now();
    const [records, applications] = await Promise.all([
      ownRecords(identityId),
      typeof repository.listApplications === "function" ? repository.listApplications() : [],
    ]);
    const applicationNames = new Map(applications.map((application) => [application.applicationId, application.displayName]));
    const current = records.find((record) => record.sessionId === currentSessionId);
    if (!current || stateOf(current, observedAt) !== "active") {
      throw new PersonalSessionError("current_session_not_active", 401);
    }
    return records.map((record) => Object.freeze({
      sessionId: record.sessionId,
      version: record.version,
      applicationId: record.applicationId,
      applicationName: applicationDisplayName(record.applicationId, applicationNames.get(record.applicationId)),
      contextLabel: record.contextLabel,
      issuedAt: record.issuedAt,
      lastSeenAt: record.lastSeenAt,
      idleExpiresAt: record.idleExpiresAt,
      absoluteExpiresAt: record.absoluteExpiresAt,
      state: stateOf(record, observedAt),
      current: record.sessionId === currentSessionId,
    }));
  }

  async function revokeOne({ identityId, currentSessionId, targetSessionId, expectedVersion }) {
    if (targetSessionId === currentSessionId) {
      throw new PersonalSessionError("current_session_requires_logout");
    }
    const records = await ownRecords(identityId);
    const target = records.find((record) => record.sessionId === targetSessionId);
    if (!target) throw new PersonalSessionError("session_not_owned", 404);
    if (target.version !== expectedVersion) throw new PersonalSessionError("session_version_conflict");
    const observedAt = now();
    if (stateOf(target, observedAt) !== "active") throw new PersonalSessionError("session_not_active");
    const targetClosure = closure(
      target, identityId, "Fermeture distante demandée depuis l’espace personnel", observedAt,
    );
    await repository.revokeApplicationSession(
      targetClosure.record, targetClosure.expectedVersion, targetClosure.auditEvent,
    );
    return Object.freeze({ revoked: 1 });
  }

  async function revokeAllOthers({ identityId, currentSessionId }) {
    const observedAt = now();
    const records = await ownRecords(identityId);
    const current = records.find((record) => record.sessionId === currentSessionId);
    if (!current || stateOf(current, observedAt) !== "active") {
      throw new PersonalSessionError("current_session_not_active", 401);
    }
    const closures = records
      .filter((record) => record.sessionId !== currentSessionId && stateOf(record, observedAt) === "active")
      .map((record) => closure(
        record,
        identityId,
        "Fermeture de toutes les autres sessions depuis l’espace personnel",
        observedAt,
      ));
    if (closures.length) await repository.revokeApplicationSessions(closures);
    return Object.freeze({ revoked: closures.length });
  }

  return Object.freeze({ listOwn, revokeOne, revokeAllOthers });
}
