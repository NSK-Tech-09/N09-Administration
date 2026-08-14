import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { PORTAL_APPLICATION_ID, PORTAL_PERMISSION } from "./portal-session-broker.mjs";

export const PORTAL_APPLICATION = Object.freeze({
  applicationId: PORTAL_APPLICATION_ID,
  displayName: "Portail NSK Tech 09",
  status: "active",
  registrationPolicy: "closed",
});

export function assertPortalProductionBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("portal production bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_prod")) {
    throw new Error("portal production bootstrap can only target production");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid portal owner identity id is required");
  }
  if (typeof justification !== "string" || justification.trim().length < 20 || justification.trim().length > 500) {
    throw new Error("an explicit production justification between 20 and 500 characters is required");
  }
}

export async function bootstrapPortalProduction(repository, {
  database, allowBootstrap, identityId, justification,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  assertPortalProductionBootstrapTarget({ database, allowBootstrap, identityId, justification });
  const identity = await repository.getIdentity(identityId);
  if (!identity || identity.status !== "active") throw new Error("portal owner identity must exist and be active");
  const created = [];
  const application = await repository.getApplication(PORTAL_APPLICATION_ID);
  if (application && JSON.stringify(application) !== JSON.stringify(PORTAL_APPLICATION)) {
    throw new Error("portal application conflicts with the controlled definition");
  }
  if (!application) {
    await repository.saveApplication(PORTAL_APPLICATION, createAuditEvent({
      action: "application.registered", result: "success", source: "portal-production-bootstrap",
      correlationId, applicationId: PORTAL_APPLICATION_ID, justification,
      newValue: { status: "active", registration_policy: "closed" },
    }));
    created.push("application");
  }
  const loginPolicy = await repository.getApplicationLoginPolicy(PORTAL_APPLICATION_ID);
  if (loginPolicy && (loginPolicy.status !== "active" || loginPolicy.requiredPermission !== PORTAL_PERMISSION)) {
    throw new Error("portal login policy conflicts with the controlled definition");
  }
  if (!loginPolicy) {
    await repository.saveApplicationLoginPolicy(PORTAL_APPLICATION_ID, PORTAL_PERMISSION, createAuditEvent({
      action: "application.login_policy_registered", result: "success", source: "portal-production-bootstrap",
      correlationId, applicationId: PORTAL_APPLICATION_ID, justification,
      newValue: { required_permission: PORTAL_PERMISSION, status: "active" },
    }));
    created.push("login_policy");
  }
  const assignments = await repository.listAssignments(identityId, PORTAL_APPLICATION_ID);
  const active = assignments.find((item) => item.status === "active");
  if (active && (active.roleId !== "portal-user" || active.scopeType !== null || active.scopeId !== null ||
      JSON.stringify([...active.permissions].sort()) !== JSON.stringify([PORTAL_PERMISSION]))) {
    throw new Error("active portal assignment conflicts with the controlled definition");
  }
  if (!active) {
    await repository.saveAssignment({
      assignmentId, subjectId: identityId, applicationId: PORTAL_APPLICATION_ID,
      roleId: "portal-user", permissions: [PORTAL_PERMISSION], scopeType: null, scopeId: null,
      conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: justification.trim(), decidedBy: null, inheritedFromGroup: null, version: 1,
    }, createAuditEvent({
      action: "assignment.created", result: "success", source: "portal-production-bootstrap",
      correlationId, subjectId: identityId, applicationId: PORTAL_APPLICATION_ID,
      roleId: "portal-user", justification,
      newValue: { status: "active", permissions: [PORTAL_PERMISSION] },
    }));
    created.push("assignment");
  }
  return { correlationId, created };
}
