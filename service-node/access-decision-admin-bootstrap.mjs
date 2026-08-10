import { randomUUID } from "node:crypto";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export function assertAccessDecisionBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("access decision bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("access decision bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

export async function bootstrapAccessDecisionAdministrator(repository, {
  database,
  allowBootstrap,
  identityId,
  justification,
  correlationId = randomUUID(),
  assignmentId = randomUUID(),
} = {}) {
  assertAccessDecisionBootstrapTarget({ database, allowBootstrap, identityId, justification });
  const [identity, application] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
  ]);
  if (!identity || identity.status !== "active") throw new Error("target identity must exist and be active");
  if (!application || application.status !== "active") throw new Error("administration application must exist and be active");

  const assignments = await repository.listAssignments(identityId, ADMIN_APPLICATION_ID);
  const equivalent = assignments.find((item) =>
    item.status === "active" && item.permissions.includes(ACCESS_DECISION_PERMISSION)
  );
  if (equivalent) return { correlationId, created: [] };

  const reason = justification.trim();
  await repository.saveAssignment({
    assignmentId,
    subjectId: identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "access-decision-administrator",
    permissions: [ACCESS_DECISION_PERMISSION],
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
    source: "access-decision-admin-bootstrap",
    correlationId,
    subjectId: identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "access-decision-administrator",
    justification: reason,
    newValue: { status: "active", permissions: [ACCESS_DECISION_PERMISSION] },
  }));
  return { correlationId, created: ["assignment"] };
}
