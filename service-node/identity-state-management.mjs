import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";
import { createAuditEvent } from "./audit.mjs";
import {
  createApplicationSessionAuditEvent,
  revokeApplicationSession,
} from "./application-session.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const IDENTITY_SUSPENSION_PERMISSION = "administration:identities:suspend";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class IdentityStateError extends Error {
  constructor(code, status = 409) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function activeSession(record, now) {
  return !record.revokedAt && new Date(record.idleExpiresAt) > now && new Date(record.absoluteExpiresAt) > now;
}

export async function authorizeIdentitySuspensionAdministration(repository, identityId, now = new Date()) {
  if (!UUID.test(String(identityId ?? ""))) return { allowed: false, reasonCode: "authentication_required" };
  const [identity, application, assignments] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.listAssignments(identityId, ADMIN_APPLICATION_ID),
  ]);
  if (!identity || !application) return { allowed: false, reasonCode: "administration_not_configured" };
  return decideAccess({
    identity,
    application,
    assignments,
    requiredPermission: IDENTITY_SUSPENSION_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}

export function createIdentityStateManagement({ repository, now = () => new Date() } = {}) {
  if (!repository || typeof repository.listIdentities !== "function" ||
      typeof repository.listApplicationSessions !== "function" ||
      typeof repository.suspendIdentityAndRevokeSessions !== "function") {
    throw new Error("identity state repository is required");
  }

  async function assertOperator(operatorIdentityId, observedAt) {
    const access = await authorizeIdentitySuspensionAdministration(repository, operatorIdentityId, observedAt);
    if (!access.allowed) throw new IdentityStateError("identity_suspension_not_allowed", 403);
  }

  async function listActive({ operatorIdentityId }) {
    const observedAt = now();
    await assertOperator(operatorIdentityId, observedAt);
    const identities = await repository.listIdentities("active");
    return Promise.all(identities.map(async (identity) => {
      const sessions = await repository.listApplicationSessions(identity.identityId);
      return Object.freeze({
        identityId: identity.identityId,
        displayName: identity.displayName,
        email: identity.email,
        status: identity.status,
        activeSessionCount: sessions.filter((record) => activeSession(record, observedAt)).length,
        current: identity.identityId === operatorIdentityId,
      });
    }));
  }

  async function suspend({
    operatorIdentityId,
    targetIdentityId,
    expectedStatus,
    justification,
    correlationId = randomUUID(),
  }) {
    if (!UUID.test(String(operatorIdentityId ?? "")) || !UUID.test(String(targetIdentityId ?? ""))) {
      throw new IdentityStateError("invalid_identity", 400);
    }
    if (expectedStatus !== "active") throw new IdentityStateError("invalid_identity_target", 400);
    const reason = typeof justification === "string" ? justification.trim() : "";
    if (reason.length < 20 || reason.length > 500) throw new IdentityStateError("invalid_justification", 400);
    if (operatorIdentityId === targetIdentityId) {
      throw new IdentityStateError("self_suspension_requires_separate_governance");
    }

    const observedAt = now();
    await assertOperator(operatorIdentityId, observedAt);
    const target = await repository.getIdentity(targetIdentityId);
    if (!target) throw new IdentityStateError("target_identity_not_found", 404);
    if (target.status !== expectedStatus) throw new IdentityStateError("identity_state_conflict");

    const sessions = (await repository.listApplicationSessions(targetIdentityId))
      .filter((record) => activeSession(record, observedAt));
    const closures = sessions.map((record) => {
      const revoked = revokeApplicationSession(record, {
        revokedByIdentityId: operatorIdentityId,
        reason,
        now: observedAt,
      });
      return {
        record: revoked,
        expectedVersion: record.version,
        auditEvent: createApplicationSessionAuditEvent({
          record: revoked,
          action: "application_session.revoked",
          actorId: operatorIdentityId,
          justification: reason,
          correlationId,
          occurredAt: observedAt,
        }),
      };
    });
    const suspended = Object.freeze({ ...target, status: "suspended" });
    const identityAuditEvent = createAuditEvent({
      action: "identity.suspended",
      result: "success",
      source: "identity-state-administration",
      correlationId,
      actorId: operatorIdentityId,
      subjectId: targetIdentityId,
      cause: "operator_suspension",
      previousValue: { status: target.status },
      newValue: { status: suspended.status, revoked_sessions: closures.length },
      justification: reason,
      occurredAt: observedAt,
    });
    await repository.suspendIdentityAndRevokeSessions({
      identity: suspended,
      expectedStatus,
      observedAt,
      identityAuditEvent,
      closures,
    });
    return Object.freeze({ correlationId, identity: suspended, revokedSessions: closures.length });
  }

  return Object.freeze({ listActive, suspend });
}
