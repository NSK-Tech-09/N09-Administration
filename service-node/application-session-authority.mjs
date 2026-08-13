import {
  assessApplicationSession,
  createApplicationSession,
  createApplicationSessionAuditEvent,
  expireApplicationSession,
  revokeApplicationSession,
  touchApplicationSession,
} from "./application-session.mjs";

function validCredential(credential) {
  return credential && typeof credential.sessionId === "string" && typeof credential.secret === "string";
}

export function createApplicationSessionAuthority({
  repository,
  config,
  now = () => new Date(),
} = {}) {
  if (!repository) throw new Error("repository is required");
  if (!config || !["disabled", "issue", "enforce"].includes(config.mode)) {
    throw new Error("invalid application session authority config");
  }

  const appliesTo = (applicationId) => applicationId === config.applicationId;
  const issuesFor = (applicationId) => config.mode !== "disabled" && appliesTo(applicationId);
  const enforcesFor = (applicationId) => config.mode === "enforce" && appliesTo(applicationId);

  async function issue({ identityId, applicationId, authenticatedAt = now() }) {
    if (!issuesFor(applicationId)) return null;
    const created = createApplicationSession({
      identityId,
      applicationId,
      idleTtlMs: config.idleTtlMs,
      absoluteTtlMs: config.absoluteTtlMs,
      contextLabel: "Connexion web N09 – Suivi des tâches",
      authenticatedAt,
      now: now(),
    });
    await repository.saveApplicationSession(created.record, createApplicationSessionAuditEvent({
      record: created.record,
      action: "application_session.created",
      justification: "Ouverture de la session applicative N09 – Suivi des tâches",
      occurredAt: new Date(created.record.issuedAt),
    }));
    return Object.freeze({
      credential: created.credential,
      idleExpiresAt: created.record.idleExpiresAt,
      absoluteExpiresAt: created.record.absoluteExpiresAt,
    });
  }

  async function closeExpired(record, reasonCode, observedAt) {
    if (record.revokedAt) return;
    const expired = expireApplicationSession(record, { reasonCode, now: observedAt });
    const audit = createApplicationSessionAuditEvent({
      record: expired,
      action: "application_session.expired",
      justification: expired.revocationReason,
      occurredAt: observedAt,
    });
    try {
      await repository.revokeApplicationSession(expired, record.version, audit);
    } catch {
      const current = await repository.getApplicationSession(record.sessionId);
      if (!current?.revokedAt) throw new Error("application session expiration could not be recorded");
    }
  }

  async function assess({ credential, identityId, applicationId }) {
    if (!enforcesFor(applicationId)) return Object.freeze({ allowed: true, reasonCode: "session_not_enforced" });
    if (!validCredential(credential)) return Object.freeze({ allowed: false, reasonCode: "session_required" });

    const observedAt = now();
    const record = await repository.getApplicationSession(credential.sessionId);
    const result = assessApplicationSession(record, {
      ...credential,
      identityId,
      applicationId,
      now: observedAt,
    });
    if (!result.allowed) {
      if (["session_idle_expired", "session_absolute_expired"].includes(result.reasonCode) && record) {
        await closeExpired(record, result.reasonCode, observedAt);
      }
      return result;
    }

    if (new Date(observedAt).valueOf() - new Date(record.lastSeenAt).valueOf() >= config.touchIntervalMs) {
      try {
        const touched = touchApplicationSession(record, { now: observedAt });
        await repository.touchApplicationSession(touched, record.version);
      } catch {
        const current = await repository.getApplicationSession(record.sessionId);
        const currentResult = assessApplicationSession(current, {
          ...credential,
          identityId,
          applicationId,
          now: observedAt,
        });
        if (!currentResult.allowed) return currentResult;
      }
    }
    return result;
  }

  async function revokeForApplication({ sessionId, identityId, applicationId, reason }) {
    if (!appliesTo(applicationId) || typeof sessionId !== "string" || !sessionId) {
      return Object.freeze({ revoked: false, reasonCode: "session_context_mismatch" });
    }
    const record = await repository.getApplicationSession(sessionId);
    if (!record || record.applicationId !== applicationId || record.identityId !== identityId) {
      return Object.freeze({ revoked: false, reasonCode: "session_unknown" });
    }
    if (record.revokedAt) return Object.freeze({ revoked: true, reasonCode: "session_already_closed" });
    const revoked = revokeApplicationSession(record, { reason, now: now() });
    await repository.revokeApplicationSession(revoked, record.version, createApplicationSessionAuditEvent({
      record: revoked,
      action: "application_session.revoked",
      justification: reason,
      occurredAt: new Date(revoked.revokedAt),
    }));
    return Object.freeze({ revoked: true, reasonCode: "session_revoked" });
  }

  return Object.freeze({ mode: config.mode, issue, assess, revokeForApplication, enforcesFor, issuesFor });
}
