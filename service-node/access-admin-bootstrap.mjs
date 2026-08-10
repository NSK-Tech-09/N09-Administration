import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export function assertAccessAdminBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("access administration bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("access administration bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  if (typeof justification !== "string" || justification.trim().length < 20 || justification.trim().length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

export async function bootstrapAccessAdministrator(repository, {
  database, allowBootstrap, identityId, justification, correlationId = randomUUID(),
  assignmentId = randomUUID(),
} = {}) {
  assertAccessAdminBootstrapTarget({ database, allowBootstrap, identityId, justification });
  const identity = await repository.getIdentity(identityId);
  if (!identity || identity.status !== "active") throw new Error("target identity must exist and be active");

  const applicationDefinition = {
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  };
  const created = [];
  const application = await repository.getApplication(ADMIN_APPLICATION_ID);
  if (application && JSON.stringify(application) !== JSON.stringify(applicationDefinition)) {
    throw new Error("administration application conflicts with the controlled definition");
  }
  if (!application) {
    await repository.saveApplication(applicationDefinition, createAuditEvent({
      action: "application.registered", result: "success", source: "access-admin-bootstrap",
      correlationId, applicationId: ADMIN_APPLICATION_ID, justification,
      newValue: { status: "active", registration_policy: "closed" },
    }));
    created.push("application");
  }

  const existingAssignments = await repository.listAssignments(identityId, ADMIN_APPLICATION_ID);
  const equivalent = existingAssignments.find((item) =>
    item.status === "active" && item.permissions.includes(ACCESS_DIRECTORY_READ_PERMISSION)
  );
  if (!equivalent) {
    await repository.saveAssignment({
      assignmentId, subjectId: identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-directory-reader", permissions: [ACCESS_DIRECTORY_READ_PERMISSION],
      scopeType: null, scopeId: null, conditions: [], status: "active",
      validFrom: null, validUntil: null, reason: justification.trim(), decidedBy: null,
      inheritedFromGroup: null, version: 1,
    }, createAuditEvent({
      action: "assignment.created", result: "success", source: "access-admin-bootstrap",
      correlationId, subjectId: identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-directory-reader", justification,
      newValue: { status: "active", permissions: [ACCESS_DIRECTORY_READ_PERMISSION] },
    }));
    created.push("assignment");
  }
  return { correlationId, created };
}
