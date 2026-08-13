import {
  assessApplicationSession,
  createApplicationSession,
  createApplicationSessionAuditEvent,
  touchApplicationSession,
} from "./application-session.mjs";

function frozenSnapshot(metrics, mode) {
  return Object.freeze({
    mode,
    enrollments: Object.freeze({ ...metrics.enrollments }),
    observations: Object.freeze({ ...metrics.observations }),
    touches: Object.freeze({ ...metrics.touches }),
  });
}

function safeLog(logger, operation, outcome, reasonCode = null) {
  const payload = { event: "application_session_shadow", operation, outcome };
  if (reasonCode) payload.reason_code = reasonCode;
  try { logger?.info?.(JSON.stringify(payload)); } catch { /* observation must remain inopposable */ }
}

export function createApplicationSessionShadow({ repository, config, now = () => new Date(), logger = console }) {
  if (!repository) throw new Error("repository is required");
  if (!config || !["disabled", "observe"].includes(config.mode)) throw new Error("invalid session shadow config");
  if (typeof now !== "function") throw new Error("now must be a function");

  const metrics = {
    enrollments: { succeeded: 0, failed: 0 },
    observations: { active: 0, notEnrolled: 0, divergent: 0, unavailable: 0 },
    touches: { succeeded: 0, failed: 0 },
  };

  async function enroll({ identityId, authenticatedAt = now(), contextLabel = "Connexion web Administration" }) {
    if (config.mode !== "observe") return null;
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
      const auditEvent = createApplicationSessionAuditEvent({
        record: created.record,
        action: "application_session.created",
        justification: "Observation inopposable de la session Administration",
        occurredAt: new Date(created.record.issuedAt),
      });
      await repository.saveApplicationSession(created.record, auditEvent);
      metrics.enrollments.succeeded += 1;
      safeLog(logger, "enroll", "succeeded");
      return created.credential;
    } catch {
      metrics.enrollments.failed += 1;
      safeLog(logger, "enroll", "failed", "registry_unavailable");
      return null;
    }
  }

  async function observe({ credential, identityId }) {
    if (config.mode !== "observe") return Object.freeze({ outcome: "disabled" });
    if (!credential?.sessionId || !credential?.secret || !identityId) {
      metrics.observations.notEnrolled += 1;
      safeLog(logger, "observe", "not_enrolled");
      return Object.freeze({ outcome: "not_enrolled" });
    }

    try {
      const observedAt = now();
      const record = await repository.getApplicationSession(credential.sessionId);
      const assessment = assessApplicationSession(record, {
        ...credential,
        identityId,
        applicationId: config.applicationId,
        now: observedAt,
      });
      if (!assessment.allowed) {
        metrics.observations.divergent += 1;
        safeLog(logger, "observe", "divergent", assessment.reasonCode);
        return Object.freeze({ outcome: "divergent", reasonCode: assessment.reasonCode });
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
        }
      }
      safeLog(logger, "observe", "active");
      return Object.freeze({ outcome: "active" });
    } catch {
      metrics.observations.unavailable += 1;
      safeLog(logger, "observe", "unavailable", "registry_unavailable");
      return Object.freeze({ outcome: "unavailable" });
    }
  }

  return Object.freeze({ enroll, observe, snapshot: () => frozenSnapshot(metrics, config.mode) });
}
