import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const ACCESS_DECISION_PERMISSION = "administration:access:decide";

export async function authorizeAccessDecisionAdministration(repository, identityId, now = new Date()) {
  if (typeof identityId !== "string" || !identityId) {
    return { allowed: false, reasonCode: "authentication_required" };
  }
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
    requiredPermission: ACCESS_DECISION_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}

function assertRevocationInput({ assignmentId, expectedVersion, operatorIdentityId, justification }) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuid.test(String(assignmentId ?? ""))) throw new Error("a valid assignment id is required");
  if (!Number.isInteger(expectedVersion) || expectedVersion < 1) throw new Error("a valid expected version is required");
  if (!uuid.test(String(operatorIdentityId ?? ""))) throw new Error("a valid operator identity id is required");
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) throw new Error("a revocation justification between 20 and 500 characters is required");
}

export async function revokeAccessAssignment(repository, {
  assignmentId,
  expectedVersion,
  operatorIdentityId,
  justification,
  correlationId = randomUUID(),
  now = new Date(),
} = {}) {
  assertRevocationInput({ assignmentId, expectedVersion, operatorIdentityId, justification });
  const operatorAccess = await authorizeAccessDecisionAdministration(repository, operatorIdentityId, now);
  if (!operatorAccess.allowed) throw new Error("operator is not allowed to decide access");

  const assignments = await repository.listAllAssignments();
  const assignment = assignments.find((item) => item.assignmentId === assignmentId);
  if (!assignment) throw new Error("assignment not found");
  if (assignment.status !== "active") throw new Error("assignment is not active");
  if (assignment.version !== expectedVersion) throw new Error("stale assignment version");

  if (assignment.applicationId === ADMIN_APPLICATION_ID && assignment.permissions.includes(ACCESS_DECISION_PERMISSION)) {
    throw new Error("access decision authority requires dedicated governance");
  }

  const reason = justification.trim();
  const revoked = {
    ...assignment,
    status: "revoked",
    reason,
    decidedBy: operatorIdentityId,
    version: assignment.version + 1,
  };
  await repository.saveAssignment(revoked, createAuditEvent({
    action: "assignment.revoked",
    result: "success",
    source: "access-administration",
    correlationId,
    actorId: operatorIdentityId,
    subjectId: assignment.subjectId,
    applicationId: assignment.applicationId,
    roleId: assignment.roleId,
    scopeType: assignment.scopeType,
    scopeId: assignment.scopeId,
    conditions: assignment.conditions,
    previousValue: { status: assignment.status, version: assignment.version },
    newValue: { status: revoked.status, version: revoked.version },
    justification: reason,
  }));
  return { correlationId, assignment: revoked };
}
