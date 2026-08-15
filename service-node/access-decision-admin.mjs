import { createHash, randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const ACCESS_DECISION_PERMISSION = "administration:access:decide";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[a-z][a-z0-9:-]{1,99}$/;

function sameStrings(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function stableAssignmentId(identityId, applicationId, roleId, scopeType, scopeId) {
  const bytes = createHash("sha256")
    .update(JSON.stringify([identityId, applicationId, roleId, scopeType, scopeId]), "utf8")
    .digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function assertGrantInput({
  identityId, applicationId, roleId, scopeType, scopeId,
  catalogVersion, operatorIdentityId, justification,
}) {
  if (!UUID.test(String(identityId ?? ""))) throw new Error("a valid target identity id is required");
  if (!IDENTIFIER.test(String(applicationId ?? ""))) throw new Error("a valid application id is required");
  if (!IDENTIFIER.test(String(roleId ?? ""))) throw new Error("a valid role id is required");
  if (!IDENTIFIER.test(String(scopeType ?? ""))) throw new Error("a valid scope type is required");
  if (scopeType === "global" && scopeId !== null) throw new Error("global scope cannot have a scope id");
  if (scopeType !== "global") {
    const normalizedScopeId = typeof scopeId === "string" ? scopeId.trim() : "";
    if (!normalizedScopeId || normalizedScopeId.length > 191 || /[\u0000-\u001f\u007f]/.test(normalizedScopeId)) {
      throw new Error("a valid scope id is required");
    }
  }
  if (!Number.isInteger(catalogVersion) || catalogVersion < 1) throw new Error("a valid catalog version is required");
  if (!UUID.test(String(operatorIdentityId ?? ""))) throw new Error("a valid operator identity id is required");
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) throw new Error("a grant justification between 20 and 500 characters is required");
}

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

export async function prepareAccessAssignment(repository, {
  identityId,
  applicationId,
  roleId,
  scopeType,
  scopeId = null,
  catalogVersion,
  operatorIdentityId,
  justification,
  correlationId = randomUUID(),
  now = new Date(),
} = {}) {
  assertGrantInput({
    identityId, applicationId, roleId, scopeType, scopeId,
    catalogVersion, operatorIdentityId, justification,
  });
  const operatorAccess = await authorizeAccessDecisionAdministration(repository, operatorIdentityId, now);
  if (!operatorAccess.allowed) throw new Error("operator is not allowed to decide access");
  if (applicationId === ADMIN_APPLICATION_ID) {
    throw new Error("administration governance assignments require a dedicated procedure");
  }

  const [identity, application, catalog, assignments] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(applicationId),
    repository.getLatestApplicationAccessCatalog(applicationId),
    repository.listAssignments(identityId, applicationId),
  ]);
  if (!identity || identity.status !== "active") throw new Error("target identity must exist and be active");
  if (!application || application.status !== "active") throw new Error("application must exist and be active");
  if (!catalog || catalog.catalogVersion !== catalogVersion) throw new Error("stale or missing application access catalog");

  const role = catalog.roles.find((item) => item.role_id === roleId);
  if (!role || role.status !== "active") throw new Error("role is not active in the published catalog");
  const scopeDefinition = catalog.scopeTypes.find((item) => item.scope_type_id === scopeType);
  if (!scopeDefinition || scopeDefinition.status !== "active" || !role.scopeTypes.includes(scopeType)) {
    throw new Error("scope is not active for the selected role");
  }
  const activePermissions = new Set(catalog.permissions
    .filter((item) => item.status === "active").map((item) => item.permission_id));
  if (role.permissions.some((permission) => !activePermissions.has(permission))) {
    throw new Error("role contains an inactive permission");
  }

  const assignmentScopeType = scopeType === "global" ? null : scopeType;
  const assignmentScopeId = scopeType === "global" ? null : scopeId.trim();
  const conditions = catalog.provisioning.readiness === "application_confirmation_required"
    ? catalog.provisioning.requirements.map((item) => item.requirement_id).sort()
    : [];
  if (catalog.provisioning.mode === "preexisting_profile_required" && conditions.length === 0) {
    throw new Error("published provisioning requirements are missing");
  }
  const sameBoundary = assignments.filter((item) =>
    item.roleId === roleId && item.scopeType === assignmentScopeType && item.scopeId === assignmentScopeId
  );
  if (sameBoundary.length > 1) throw new Error("duplicate historical assignments require reconciliation");
  const previous = sameBoundary[0] ?? null;
  if (previous?.status === "active") {
    if (!sameStrings(previous.permissions, role.permissions) || !sameStrings(previous.conditions, conditions)) {
      throw new Error("active assignment does not match the published catalog");
    }
    return { correlationId, assignment: previous, auditEvent: null, created: false };
  }

  const reason = justification.trim();
  const granted = {
    assignmentId: previous?.assignmentId ?? stableAssignmentId(
      identityId, applicationId, roleId, assignmentScopeType, assignmentScopeId,
    ),
    subjectId: identityId,
    applicationId,
    roleId,
    permissions: [...role.permissions].sort(),
    scopeType: assignmentScopeType,
    scopeId: assignmentScopeId,
    conditions,
    status: "active",
    validFrom: null,
    validUntil: null,
    reason,
    decidedBy: operatorIdentityId,
    inheritedFromGroup: null,
    version: previous ? previous.version + 1 : 1,
  };
  const auditEvent = createAuditEvent({
    action: "assignment.granted",
    result: "success",
    source: "access-administration",
    correlationId,
    actorId: operatorIdentityId,
    subjectId: identityId,
    applicationId,
    roleId,
    scopeType: assignmentScopeType,
    scopeId: assignmentScopeId,
    conditions,
    previousValue: previous ? { status: previous.status, version: previous.version } : null,
    newValue: {
      status: granted.status,
      version: granted.version,
      permissions: granted.permissions,
      catalog_version: catalog.catalogVersion,
      application_confirmation_required: conditions.length > 0,
    },
    justification: reason,
  });
  return { correlationId, assignment: granted, auditEvent, created: true };
}

export async function grantAccessAssignment(repository, input = {}) {
  const prepared = await prepareAccessAssignment(repository, input);
  if (prepared.created) await repository.saveAssignment(prepared.assignment, prepared.auditEvent);
  return {
    correlationId: prepared.correlationId,
    assignment: prepared.assignment,
    created: prepared.created,
  };
}
