import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { ADMIN_APPLICATION_ID, LINK_DECISION_PERMISSION } from "./identity-link-admin.mjs";
import {
  IDENTITY_DISABLEMENT_PERMISSION,
  IDENTITY_REACTIVATION_PERMISSION,
  IDENTITY_SUSPENSION_PERMISSION,
} from "./identity-state-management.mjs";
import { NOTIFICATION_OPERATIONS_READ_PERMISSION } from "./notification-operations-admin.mjs";
import { SESSION_REVOCATION_PERMISSION } from "./operator-session-management.mjs";

export const LEGAL_OWNER_EMAIL = "f.travers@nsktech.fr";
export const LEGAL_OWNER_CONFIRMATION = "GRANT_NSK_LEGAL_OWNER_AUTHORITY";

export const RESPONSIBLE_AUTHORITY_POWERS = Object.freeze([
  Object.freeze({
    roleId: "identity-link-administrator", permission: LINK_DECISION_PERMISSION,
    label: "Rattachements d’identité", description: "Approuver ou refuser les rattachements externes.",
    href: "/admin/link-requests",
  }),
  Object.freeze({
    roleId: "access-directory-reader", permission: ACCESS_DIRECTORY_READ_PERMISSION,
    label: "Registre des accès", description: "Consulter les identités, applications, rôles et affectations.",
    href: "/admin/access",
  }),
  Object.freeze({
    roleId: "access-decision-administrator", permission: ACCESS_DECISION_PERMISSION,
    label: "Décisions d’accès", description: "Accorder ou révoquer les rôles applicatifs gouvernés.",
    href: "/admin/access-decisions",
  }),
  Object.freeze({
    roleId: "notification-operations-reader", permission: NOTIFICATION_OPERATIONS_READ_PERMISSION,
    label: "Supervision des notifications", description: "Contrôler les traitements et anomalies du centre de notifications.",
    href: "/admin/notification-operations",
  }),
  Object.freeze({
    roleId: "session-revocation-administrator", permission: SESSION_REVOCATION_PERMISSION,
    label: "Sessions actives", description: "Superviser et fermer les sessions applicatives.",
    href: "/admin/sessions",
  }),
  Object.freeze({
    roleId: "identity-suspension-administrator", permission: IDENTITY_SUSPENSION_PERMISSION,
    label: "Suspension des identités", description: "Suspendre une identité et fermer ses sessions.",
    href: "/admin/identities",
  }),
  Object.freeze({
    roleId: "identity-reactivation-administrator", permission: IDENTITY_REACTIVATION_PERMISSION,
    label: "Réactivation des identités", description: "Réactiver une identité sans restaurer ses anciennes sessions.",
    href: "/admin/identities",
  }),
  Object.freeze({
    roleId: "identity-disablement-administrator", permission: IDENTITY_DISABLEMENT_PERMISSION,
    label: "Sorties de l’écosystème", description: "Désactiver une identité et révoquer tous ses accès.",
    href: "/admin/identities",
  }),
]);

function normalizedEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export async function assessResponsibleAuthority(repository, identityId, now = new Date()) {
  const [identity, application, assignments] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.listAssignments(identityId, ADMIN_APPLICATION_ID),
  ]);
  const powers = RESPONSIBLE_AUTHORITY_POWERS.map((power) => ({
    ...power,
    allowed: Boolean(identity && application && decideAccess({
      identity, application, assignments, requiredPermission: power.permission,
      scopeType: null, scopeId: null, now,
    }).allowed),
  }));
  return Object.freeze({
    identity,
    legalOwner: normalizedEmail(identity?.email) === LEGAL_OWNER_EMAIL,
    complete: powers.every((power) => power.allowed),
    grantedCount: powers.filter((power) => power.allowed).length,
    totalCount: powers.length,
    powers: Object.freeze(powers.map(Object.freeze)),
  });
}

function assertGrantTarget({ database, environment, allowGrant, confirmation, email, justification }) {
  if (environment !== "production") throw new Error("legal owner authority requires production");
  if (typeof database !== "string" || !database.endsWith("_prod")) {
    throw new Error("legal owner authority requires the explicit production database");
  }
  if (allowGrant !== "true" || confirmation !== LEGAL_OWNER_CONFIRMATION) {
    throw new Error("legal owner authority is not explicitly confirmed");
  }
  if (normalizedEmail(email) !== LEGAL_OWNER_EMAIL) throw new Error("unexpected legal owner email");
  const reason = typeof justification === "string" ? justification.trim() : "";
  if (reason.length < 30 || reason.length > 500) {
    throw new Error("an explicit legal owner justification between 30 and 500 characters is required");
  }
  return reason;
}

export async function grantResponsibleAuthority(repository, {
  database, environment, allowGrant, confirmation, email, justification,
  correlationId = randomUUID(), assignmentId = () => randomUUID(),
} = {}) {
  const reason = assertGrantTarget({ database, environment, allowGrant, confirmation, email, justification });
  const [identity, application, catalog] = await Promise.all([
    repository.findIdentityByEmail(normalizedEmail(email)),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID),
  ]);
  if (!identity || identity.status !== "active") throw new Error("legal owner identity must exist and be active");
  if (!application || application.status !== "active") throw new Error("administration application must be active");
  if (!catalog || catalog.catalogVersion < 7) throw new Error("administration catalog v7 is required");

  for (const power of RESPONSIBLE_AUTHORITY_POWERS) {
    const role = catalog.roles.find((item) => item.role_id === power.roleId);
    const permission = catalog.permissions.find((item) => item.permission_id === power.permission);
    if (role?.status !== "active" || permission?.status !== "active" ||
        !role.permissions.includes(power.permission) || !role.scopeTypes.includes("global")) {
      throw new Error(`responsible authority role is not publishable: ${power.roleId}`);
    }
  }

  const assignments = await repository.listAssignments(identity.identityId, ADMIN_APPLICATION_ID);
  const created = [];
  const unchanged = [];
  for (const power of RESPONSIBLE_AUTHORITY_POWERS) {
    const active = assignments.filter((item) =>
      item.status === "active" && item.permissions.includes(power.permission)
    );
    if (active.length > 1) throw new Error(`duplicate active authority: ${power.permission}`);
    if (active.length === 1) {
      unchanged.push(power.roleId);
      continue;
    }
    await repository.saveAssignment({
      assignmentId: assignmentId(power), subjectId: identity.identityId,
      applicationId: ADMIN_APPLICATION_ID, roleId: power.roleId,
      permissions: [power.permission], scopeType: null, scopeId: null, conditions: [],
      status: "active", validFrom: null, validUntil: null, reason,
      decidedBy: null, inheritedFromGroup: null, version: 1,
    }, createAuditEvent({
      action: "assignment.created", result: "success", source: "legal-owner-authority",
      correlationId, subjectId: identity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: power.roleId, justification: reason,
      newValue: { status: "active", permissions: [power.permission], legal_owner_authority: true },
    }));
    created.push(power.roleId);
  }
  return Object.freeze({ correlationId, identityId: identity.identityId, created, unchanged });
}
