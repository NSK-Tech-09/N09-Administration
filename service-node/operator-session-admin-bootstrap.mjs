import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { SESSION_REVOCATION_PERMISSION } from "./operator-session-management.mjs";

export function assertOperatorSessionBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("operator session bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("operator session bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

export async function bootstrapOperatorSessionAdministrator(repository, {
  database,
  allowBootstrap,
  identityId,
  justification,
  correlationId = randomUUID(),
  assignmentId = randomUUID(),
} = {}) {
  assertOperatorSessionBootstrapTarget({ database, allowBootstrap, identityId, justification });
  const [identity, application, catalog] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID),
  ]);
  if (!identity || identity.status !== "active") throw new Error("target identity must exist and be active");
  if (!application || application.status !== "active") throw new Error("administration application must exist and be active");
  const role = catalog?.roles.find((item) => item.role_id === "session-revocation-administrator");
  const permission = catalog?.permissions.find((item) => item.permission_id === SESSION_REVOCATION_PERMISSION);
  if (!catalog || catalog.catalogVersion < 4 || role?.status !== "active" || permission?.status !== "active" ||
      !role.permissions.includes(SESSION_REVOCATION_PERMISSION) || !role.scopeTypes.includes("global")) {
    throw new Error("session revocation role must be active in administration catalog v4");
  }

  const assignments = await repository.listAssignments(identityId, ADMIN_APPLICATION_ID);
  const equivalent = assignments.find((item) =>
    item.status === "active" && item.permissions.includes(SESSION_REVOCATION_PERMISSION)
  );
  if (equivalent) return { correlationId, created: [] };

  const reason = justification.trim();
  await repository.saveAssignment({
    assignmentId,
    subjectId: identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "session-revocation-administrator",
    permissions: [SESSION_REVOCATION_PERMISSION],
    scopeType: null,
    scopeId: null,
    conditions: [],
    status: "active",
    validFrom: null,
    validUntil: null,
    reason,
    decidedBy: null,
    inheritedFromGroup: null,
    version: 1,
  }, createAuditEvent({
    action: "assignment.created",
    result: "success",
    source: "operator-session-bootstrap",
    correlationId,
    subjectId: identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "session-revocation-administrator",
    justification: reason,
    newValue: { status: "active", permissions: [SESSION_REVOCATION_PERMISSION] },
  }));
  return { correlationId, created: ["assignment"] };
}
