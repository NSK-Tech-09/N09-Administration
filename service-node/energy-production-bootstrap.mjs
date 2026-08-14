import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

export const ENERGY_APPLICATION = Object.freeze({
  applicationId: "n09-energie",
  displayName: "N09 – Énergie",
  status: "active",
  registrationPolicy: "closed",
});

export const ENERGY_PERMISSIONS = Object.freeze(["energy:read", "energy:write"]);
export const ENERGY_PRODUCTION_REDIRECT_URI = "https://energie.nsktech.fr/auth/nsk/callback";

export function assertEnergyProductionBootstrapTarget({
  database, allowBootstrap, identityId, justification, redirectUri,
}) {
  if (allowBootstrap !== "true") throw new Error("energy production bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_prod")) {
    throw new Error("energy production bootstrap can only target production");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid energy owner identity id is required");
  }
  if (typeof justification !== "string" || justification.trim().length < 20 || justification.trim().length > 500) {
    throw new Error("an explicit production justification between 20 and 500 characters is required");
  }
  if (redirectUri !== ENERGY_PRODUCTION_REDIRECT_URI) {
    throw new Error("energy login redirect must be the controlled production callback URI");
  }
}

export async function bootstrapEnergyProduction(repository, {
  database, allowBootstrap, identityId, justification, redirectUri,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  assertEnergyProductionBootstrapTarget({ database, allowBootstrap, identityId, justification, redirectUri });
  const identity = await repository.getIdentity(identityId);
  if (!identity || identity.status !== "active") throw new Error("energy owner identity must exist and be active");

  const created = [];
  const application = await repository.getApplication(ENERGY_APPLICATION.applicationId);
  if (application && JSON.stringify(application) !== JSON.stringify(ENERGY_APPLICATION)) {
    throw new Error("energy application conflicts with the controlled definition");
  }
  if (!application) {
    await repository.saveApplication(ENERGY_APPLICATION, createAuditEvent({
      action: "application.registered", result: "success", source: "energy-production-bootstrap",
      correlationId, applicationId: ENERGY_APPLICATION.applicationId, justification,
      newValue: { status: "active", registration_policy: "closed" },
    }));
    created.push("application");
  }

  const registeredRedirect = await repository.getApplicationRedirectUri(ENERGY_APPLICATION.applicationId, redirectUri);
  if (registeredRedirect && registeredRedirect.status !== "active") {
    throw new Error("energy login redirect exists but is not active");
  }
  if (!registeredRedirect) {
    await repository.saveApplicationRedirectUri(ENERGY_APPLICATION.applicationId, redirectUri, createAuditEvent({
      action: "application.redirect_uri_registered", result: "success", source: "energy-production-bootstrap",
      correlationId, applicationId: ENERGY_APPLICATION.applicationId, justification,
      newValue: { redirect_uri: redirectUri, status: "active" },
    }));
    created.push("redirect_uri");
  }

  const loginPolicy = await repository.getApplicationLoginPolicy(ENERGY_APPLICATION.applicationId);
  if (loginPolicy && (loginPolicy.status !== "active" || loginPolicy.requiredPermission !== ENERGY_PERMISSIONS[0])) {
    throw new Error("energy login policy conflicts with the controlled definition");
  }
  if (!loginPolicy) {
    await repository.saveApplicationLoginPolicy(ENERGY_APPLICATION.applicationId, ENERGY_PERMISSIONS[0], createAuditEvent({
      action: "application.login_policy_registered", result: "success", source: "energy-production-bootstrap",
      correlationId, applicationId: ENERGY_APPLICATION.applicationId, justification,
      newValue: { required_permission: ENERGY_PERMISSIONS[0], status: "active" },
    }));
    created.push("login_policy");
  }

  const assignments = await repository.listAssignments(identityId, ENERGY_APPLICATION.applicationId);
  const active = assignments.find((item) => item.status === "active");
  if (active && (
    active.roleId !== "energy-owner" || active.scopeType !== null || active.scopeId !== null ||
    JSON.stringify([...active.permissions].sort()) !== JSON.stringify([...ENERGY_PERMISSIONS].sort())
  )) throw new Error("active energy assignment conflicts with the controlled definition");
  if (!active) {
    await repository.saveAssignment({
      assignmentId, subjectId: identityId, applicationId: ENERGY_APPLICATION.applicationId,
      roleId: "energy-owner", permissions: [...ENERGY_PERMISSIONS],
      scopeType: null, scopeId: null, conditions: [], status: "active",
      validFrom: null, validUntil: null, reason: justification.trim(), decidedBy: null,
      inheritedFromGroup: null, version: 1,
    }, createAuditEvent({
      action: "assignment.created", result: "success", source: "energy-production-bootstrap",
      correlationId, subjectId: identityId, applicationId: ENERGY_APPLICATION.applicationId,
      roleId: "energy-owner", justification,
      newValue: { status: "active", permissions: [...ENERGY_PERMISSIONS] },
    }));
    created.push("assignment");
  }

  return { correlationId, created };
}
