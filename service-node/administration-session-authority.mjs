import {
  assessApplicationSession,
  createApplicationSession,
  createApplicationSessionAuditEvent,
  expireApplicationSession,
  revokeApplicationSession,
  touchApplicationSession,
} from "./application-session.mjs";

function frozenSnapshot(metrics, mode) {
  return Object.freeze({
    mode,
    enrollments: Object.freeze({ ...metrics.enrollments }),
    observations: Object.freeze({ ...metrics.observations }),
    touches: Object.freeze({ ...metrics.touches }),
    revocations: Object.freeze({ ...metrics.revocations }),
  });
}

function safeLog(logger, operation, outcome, reasonCode = null) {
  const payload = { event: "administration_session_authority", operation, outcome };
  if (reasonCode) payload.reason_code = reasonCode;
  try { logger?.info?.(JSON.stringify(payload)); } catch { /* never influence access */ }
}

function validCredential(credential) {
  return credential && typeof credential.sessionId === "string" && typeof credential.secret === "string";
}

export function createAdministrationSessionAuthority({
  repository,
  config,
  now = () => new Date(),
  logger = console,
} = {}) {
  if (!repository) throw new Error("repository is required");
  if (!config || !["disabled", "observe", "enforce"].includes(config.mode)) {
    throw new Error("invalid administration session authority config");
  }
  if (typeof now !== "function") throw new Error("now must be a function");

  const metrics = {
    enrollments: { succeeded: 0, failed: 0 },
    observations: { active: 0, notEnrolled: 0, divergent: 0, unavailable: 0 },
    touches: { succeeded: 0, failed: 0 },
    revocations: { succeeded: 0, failed: 0 },
  };

  async function issue({ identityId, authenticatedAt = now(), contextLabel = "Connexion web Administration" }) {
    if (config.mode === "disabled") return null;
    try {
      const created = createApplicationSession({
        identityId,
        applicationId: config.applicationId,
        idleTtlMs: config.idleTtlMs,
        absoluteTtlMs: config.absoluteTtlMs,
        contextLabel,
        authenticatedAt,
        now: now(),
      });
      await repository.saveApplicationSession(created.record, createApplicationSessionAuditEvent({
        record: created.record,
        action: "application_session.created",
        justification: config.mode === "observe"
          ? "Observation inopposable de la session Administration"
          : "Ouverture de la session opposable Administration",
        occurredAt: new Date(created.record.issuedAt),
      }));
      metrics.enrollments.succeeded += 1;
      safeLog(logger, "issue", "succeeded");
      return created.credential;
    } catch (error) {
      metrics.enrollments.failed += 1;
      safeLog(logger, "issue", "failed", "registry_unavailable");
      if (config.mode === "enforce") throw new Error("administration_session_registry_unavailable", { cause: error });
      return null;
    }
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
      if (!current?.revokedAt) throw new Error("administration session expiration could not be recorded");
    }
  }

  async function evaluate({ credential, identityId, enforce }) {
    if (!validCredential(credential) || !identityId) {
      metrics.observations.notEnrolled += 1;
      safeLog(logger, enforce ? "assess" : "observe", "not_enrolled");
      return Object.freeze({
        allowed: !enforce,
        outcome: "not_enrolled",
        reasonCode: "session_required",
      });
    }
    try {
      const observedAt = now();
      const record = await repository.getApplicationSession(credential.sessionId);
      const result = assessApplicationSession(record, {
        ...credential,
        identityId,
        applicationId: config.applicationId,
        now: observedAt,
      });
      if (!result.allowed) {
        if (["session_idle_expired", "session_absolute_expired"].includes(result.reasonCode) && record) {
          await closeExpired(record, result.reasonCode, observedAt);
        }
        metrics.observations.divergent += 1;
        safeLog(logger, enforce ? "assess" : "observe", "divergent", result.reasonCode);
        return Object.freeze({ allowed: !enforce, outcome: "divergent", reasonCode: result.reasonCode });
      }

      metrics.observations.active += 1;
      if (new Date(observedAt).valueOf() - new Date(record.lastSeenAt).valueOf() >= config.touchIntervalMs) {
        try {
          const touched = touchApplicationSession(record, { now: observedAt });
          await repository.touchApplicationSession(touched, record.version);
          metrics.touches.succeeded += 1;
          safeLog(logger, "touch", "succeeded");
        } catch {
          metrics.touches.failed += 1;
          safeLog(logger, "touch", "failed", "concurrent_or_unavailable");
          if (enforce) {
            const current = await repository.getApplicationSession(record.sessionId);
            const currentResult = assessApplicationSession(current, {
              ...credential,
              identityId,
              applicationId: config.applicationId,
              now: observedAt,
            });
            if (!currentResult.allowed) {
              metrics.observations.divergent += 1;
              safeLog(logger, "assess", "divergent", currentResult.reasonCode);
              return Object.freeze({
                allowed: false,
                outcome: "divergent",
                reasonCode: currentResult.reasonCode,
              });
            }
          }
        }
      }
      safeLog(logger, enforce ? "assess" : "observe", "active");
      return Object.freeze({ allowed: true, outcome: "active", reasonCode: "session_active" });
    } catch {
      metrics.observations.unavailable += 1;
      safeLog(logger, enforce ? "assess" : "observe", "unavailable", "registry_unavailable");
      return Object.freeze({
        allowed: !enforce,
        outcome: "unavailable",
        reasonCode: "session_registry_unavailable",
      });
    }
  }

  async function observe({ credential, identityId }) {
    if (config.mode !== "observe") return Object.freeze({ outcome: "disabled" });
    const result = await evaluate({ credential, identityId, enforce: false });
    return Object.freeze({ outcome: result.outcome, ...(result.outcome === "divergent" ? { reasonCode: result.reasonCode } : {}) });
  }

  async function assess({ credential, identityId }) {
    if (config.mode !== "enforce") {
      return Object.freeze({ allowed: true, reasonCode: "session_not_enforced" });
    }
    return evaluate({ credential, identityId, enforce: true });
  }

  async function revokeCurrent({ credential, identityId, reason = "Déconnexion de la session Administration" }) {
    if (config.mode !== "enforce" || !validCredential(credential) || !identityId) {
      return Object.freeze({ revoked: config.mode !== "enforce", reasonCode: "session_not_enforced" });
    }
    try {
      const record = await repository.getApplicationSession(credential.sessionId);
      if (!record || record.identityId !== identityId || record.applicationId !== config.applicationId) {
        return Object.freeze({ revoked: false, reasonCode: "session_unknown" });
      }
      if (record.revokedAt) return Object.freeze({ revoked: true, reasonCode: "session_already_closed" });
      const revoked = revokeApplicationSession(record, {
        revokedByIdentityId: identityId,
        reason,
        now: now(),
      });
      await repository.revokeApplicationSession(revoked, record.version, createApplicationSessionAuditEvent({
        record: revoked,
        action: "application_session.revoked",
        actorId: identityId,
        justification: reason,
        occurredAt: new Date(revoked.revokedAt),
      }));
      metrics.revocations.succeeded += 1;
      safeLog(logger, "revoke", "succeeded");
      return Object.freeze({ revoked: true, reasonCode: "session_revoked" });
    } catch {
      metrics.revocations.failed += 1;
      safeLog(logger, "revoke", "failed", "registry_unavailable");
      return Object.freeze({ revoked: false, reasonCode: "session_registry_unavailable" });
    }
  }

  return Object.freeze({
    mode: config.mode,
    issue,
    enroll: issue,
    observe,
    assess,
    revokeCurrent,
    snapshot: () => frozenSnapshot(metrics, config.mode),
  });
}
