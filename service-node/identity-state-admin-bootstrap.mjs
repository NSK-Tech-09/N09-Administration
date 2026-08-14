import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  IDENTITY_DISABLEMENT_PERMISSION,
  IDENTITY_REACTIVATION_PERMISSION,
  IDENTITY_SUSPENSION_PERMISSION,
} from "./identity-state-management.mjs";

export function assertIdentityStateBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("identity state bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("identity state bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

export function assertIdentityReactivationBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("identity reactivation bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("identity reactivation bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

export function assertIdentityDisablementBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("identity disablement bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("identity disablement bootstrap can only target preproduction");
  }
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid target identity id is required");
  }
  const length = typeof justification === "string" ? justification.trim().length : 0;
  if (length < 20 || length > 500) {
    throw new Error("an explicit bootstrap justification between 20 and 500 characters is required");
  }
}

async function bootstrapIdentityStateAdministrator(repository, {
  database, allowBootstrap, identityId, justification, correlationId, assignmentId,
  assertTarget, roleId, permission, minimumCatalogVersion, source,
}) {
  assertTarget({ database, allowBootstrap, identityId, justification });
  const [identity, application, catalog] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID),
  ]);
  if (!identity || identity.status !== "active") throw new Error("target identity must exist and be active");
  if (!application || application.status !== "active") throw new Error("administration application must exist and be active");
  const role = catalog?.roles.find((item) => item.role_id === roleId);
  const catalogPermission = catalog?.permissions.find((item) => item.permission_id === permission);
  if (!catalog || catalog.catalogVersion < minimumCatalogVersion || role?.status !== "active" ||
      catalogPermission?.status !== "active" || !role.permissions.includes(permission) ||
      !role.scopeTypes.includes("global")) {
    throw new Error(`${roleId} must be active in administration catalog v${minimumCatalogVersion}`);
  }
  const equivalent = (await repository.listAssignments(identityId, ADMIN_APPLICATION_ID)).find((item) =>
    item.status === "active" && item.permissions.includes(permission)
  );
  if (equivalent) return { correlationId, created: [] };
  const reason = justification.trim();
  await repository.saveAssignment({
    assignmentId, subjectId: identityId, applicationId: ADMIN_APPLICATION_ID,
    roleId, permissions: [permission], scopeType: null, scopeId: null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason, decidedBy: null, inheritedFromGroup: null, version: 1,
  }, createAuditEvent({
    action: "assignment.created", result: "success", source, correlationId,
    subjectId: identityId, applicationId: ADMIN_APPLICATION_ID, roleId,
    justification: reason, newValue: { status: "active", permissions: [permission] },
  }));
  return { correlationId, created: ["assignment"] };
}

export async function bootstrapIdentitySuspensionAdministrator(repository, {
  database, allowBootstrap, identityId, justification,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  return bootstrapIdentityStateAdministrator(repository, {
    database, allowBootstrap, identityId, justification, correlationId, assignmentId,
    assertTarget: assertIdentityStateBootstrapTarget,
    roleId: "identity-suspension-administrator",
    permission: IDENTITY_SUSPENSION_PERMISSION,
    minimumCatalogVersion: 5,
    source: "identity-state-bootstrap",
  });
}

export async function bootstrapIdentityReactivationAdministrator(repository, {
  database, allowBootstrap, identityId, justification,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  return bootstrapIdentityStateAdministrator(repository, {
    database, allowBootstrap, identityId, justification, correlationId, assignmentId,
    assertTarget: assertIdentityReactivationBootstrapTarget,
    roleId: "identity-reactivation-administrator",
    permission: IDENTITY_REACTIVATION_PERMISSION,
    minimumCatalogVersion: 6,
    source: "identity-reactivation-bootstrap",
  });
}

export async function bootstrapIdentityDisablementAdministrator(repository, {
  database, allowBootstrap, identityId, justification,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  return bootstrapIdentityStateAdministrator(repository, {
    database, allowBootstrap, identityId, justification, correlationId, assignmentId,
    assertTarget: assertIdentityDisablementBootstrapTarget,
    roleId: "identity-disablement-administrator",
    permission: IDENTITY_DISABLEMENT_PERMISSION,
    minimumCatalogVersion: 7,
    source: "identity-disablement-bootstrap",
  });
}
