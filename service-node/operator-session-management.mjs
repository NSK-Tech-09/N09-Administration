import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";
import {
  createApplicationSessionAuditEvent,
  revokeApplicationSession,
} from "./application-session.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const SESSION_REVOCATION_PERMISSION = "administration:sessions:revoke";

export class OperatorSessionError extends Error {
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

function validIdentityId(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

export async function authorizeSessionRevocationAdministration(repository, identityId, now = new Date()) {
  if (!validIdentityId(identityId)) return { allowed: false, reasonCode: "authentication_required" };
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
    requiredPermission: SESSION_REVOCATION_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}

export function createOperatorSessionManagement({ repository, now = () => new Date() } = {}) {
  if (!repository || typeof repository.listIdentities !== "function" ||
      typeof repository.listApplications !== "function" ||
      typeof repository.listAllApplicationSessions !== "function" ||
      typeof repository.listApplicationSessions !== "function" ||
      typeof repository.revokeApplicationSession !== "function") {
    throw new Error("operator session repository is required");
  }

  async function assertOperator(operatorIdentityId, observedAt) {
    const access = await authorizeSessionRevocationAdministration(repository, operatorIdentityId, observedAt);
    if (!access.allowed) throw new OperatorSessionError("session_revocation_not_allowed", 403);
  }

  async function listActive({ operatorIdentityId, currentSessionId }) {
    const observedAt = now();
    await assertOperator(operatorIdentityId, observedAt);
    const [identities, applications, records] = await Promise.all([
      repository.listIdentities(),
      repository.listApplications(),
      repository.listAllApplicationSessions(),
    ]);
    const identitiesById = new Map(identities.map((identity) => [identity.identityId, identity]));
    const applicationNames = new Map(applications.map((application) => [application.applicationId, application.displayName]));
    return records
      .filter((record) => stateOf(record, observedAt) === "active" && identitiesById.has(record.identityId))
      .map((record) => {
        const identity = identitiesById.get(record.identityId);
        return Object.freeze({
          sessionId: record.sessionId,
          version: record.version,
          identityId: identity.identityId,
          identityName: identity.displayName,
          identityEmail: identity.email,
          identityStatus: identity.status,
          applicationId: record.applicationId,
          applicationName: applicationNames.get(record.applicationId) || record.applicationId,
          contextLabel: record.contextLabel,
          issuedAt: record.issuedAt,
          lastSeenAt: record.lastSeenAt,
          idleExpiresAt: record.idleExpiresAt,
          absoluteExpiresAt: record.absoluteExpiresAt,
          current: record.identityId === operatorIdentityId && record.sessionId === currentSessionId,
        });
      })
      .sort((left, right) => String(right.lastSeenAt).localeCompare(String(left.lastSeenAt)));
  }

  async function revokeOne({
    operatorIdentityId,
    currentSessionId,
    targetIdentityId,
    targetSessionId,
    expectedVersion,
    justification,
    correlationId = randomUUID(),
  }) {
    if (!validIdentityId(operatorIdentityId) || !validIdentityId(targetIdentityId)) {
      throw new OperatorSessionError("invalid_identity", 400);
    }
    if (!validIdentityId(targetSessionId) || !Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw new OperatorSessionError("invalid_session_target", 400);
    }
    const reason = typeof justification === "string" ? justification.trim() : "";
    if (reason.length < 20 || reason.length > 500) {
      throw new OperatorSessionError("invalid_justification", 400);
    }
    const observedAt = now();
    await assertOperator(operatorIdentityId, observedAt);
    if (operatorIdentityId === targetIdentityId && currentSessionId === targetSessionId) {
      throw new OperatorSessionError("current_session_requires_logout");
    }
    const targetIdentity = await repository.getIdentity(targetIdentityId);
    if (!targetIdentity) throw new OperatorSessionError("target_identity_not_found", 404);
    const target = (await repository.listApplicationSessions(targetIdentityId))
      .find((record) => record.sessionId === targetSessionId);
    if (!target) throw new OperatorSessionError("session_not_in_target_scope", 404);
    if (target.version !== expectedVersion) throw new OperatorSessionError("session_version_conflict");
    if (stateOf(target, observedAt) !== "active") throw new OperatorSessionError("session_not_active");

    const revoked = revokeApplicationSession(target, {
      revokedByIdentityId: operatorIdentityId,
      reason,
      now: observedAt,
    });
    await repository.revokeApplicationSession(revoked, target.version, createApplicationSessionAuditEvent({
      record: revoked,
      action: "application_session.revoked",
      actorId: operatorIdentityId,
      justification: reason,
      correlationId,
      occurredAt: observedAt,
    }));
    return Object.freeze({ correlationId, revoked: 1 });
  }

  return Object.freeze({ listActive, revokeOne });
}
