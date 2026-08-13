import { randomUUID } from "node:crypto";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { ADMIN_APPLICATION_ID, LINK_DECISION_PERMISSION } from "./identity-link-admin.mjs";
import { NOTIFICATION_OPERATIONS_READ_PERMISSION } from "./notification-operations-admin.mjs";
import { SESSION_REVOCATION_PERMISSION } from "./operator-session-management.mjs";

export const ADMINISTRATION_ACCESS_CATALOG_V1 = Object.freeze({
  application_id: ADMIN_APPLICATION_ID,
  catalog_version: 1,
  permissions: [
    { permission_id: LINK_DECISION_PERMISSION, display_name: "Décider les rattachements d’identité", description: "Approuver ou refuser le rattachement d’une preuve externe à une identité NSK active.", status: "active" },
    { permission_id: ACCESS_DIRECTORY_READ_PERMISSION, display_name: "Consulter le registre des accès", description: "Consulter en lecture seule les identités, applications, catalogues et affectations centrales.", status: "active" },
    { permission_id: ACCESS_DECISION_PERMISSION, display_name: "Décider les révocations d’accès", description: "Révoquer une affectation centrale existante dans la frontière de gouvernance autorisée.", status: "active" },
  ],
  scope_types: [
    { scope_type_id: "global", display_name: "Administration centrale", description: "Périmètre global de gouvernance de N09 – Administration.", status: "active" },
  ],
  roles: [
    { role_id: "identity-link-administrator", display_name: "Responsable des rattachements", description: "Traite les demandes de rattachement sans accorder de droit applicatif.", status: "active", permissions: [LINK_DECISION_PERMISSION], scope_types: ["global"] },
    { role_id: "access-directory-reader", display_name: "Lecteur du registre des accès", description: "Consulte le registre central sans pouvoir le modifier.", status: "active", permissions: [ACCESS_DIRECTORY_READ_PERMISSION], scope_types: ["global"] },
    { role_id: "access-decision-administrator", display_name: "Responsable des révocations", description: "Décide les révocations autorisées sans pouvoir créer un octroi arbitraire.", status: "active", permissions: [ACCESS_DECISION_PERMISSION], scope_types: ["global"] },
  ],
  provisioning: {
    mode: "central_identity_only", identity_key: "identity_id", readiness: "immediate",
    automatic_profile_creation: false, email_matching: "forbidden", requirements: [],
  },
});

export const ADMINISTRATION_ACCESS_CATALOG_V2 = Object.freeze({
  ...ADMINISTRATION_ACCESS_CATALOG_V1,
  catalog_version: 2,
  permissions: ADMINISTRATION_ACCESS_CATALOG_V1.permissions.map((permission) =>
    permission.permission_id === ACCESS_DECISION_PERMISSION
      ? { ...permission, display_name: "Décider les accès applicatifs", description: "Accorder un rôle applicatif actif publié par son propriétaire ou révoquer une affectation centrale existante, avec preuve auditée." }
      : permission
  ),
  roles: ADMINISTRATION_ACCESS_CATALOG_V1.roles.map((role) =>
    role.role_id === "access-decision-administrator"
      ? { ...role, display_name: "Responsable des accès applicatifs", description: "Accorde les rôles applicatifs actifs et décide les révocations autorisées, sans administrer les pouvoirs centraux protégés." }
      : role
  ),
});

export const ADMINISTRATION_ACCESS_CATALOG_V3 = Object.freeze({
  ...ADMINISTRATION_ACCESS_CATALOG_V2,
  catalog_version: 3,
  permissions: [
    ...ADMINISTRATION_ACCESS_CATALOG_V2.permissions,
    {
      permission_id: NOTIFICATION_OPERATIONS_READ_PERMISSION,
      display_name: "Consulter l’exploitation des notifications",
      description: "Consulter en lecture seule la file, les résolutions, les quarantaines et le blocage des canaux externes.",
      status: "active",
    },
  ],
  roles: [
    ...ADMINISTRATION_ACCESS_CATALOG_V2.roles,
    {
      role_id: "notification-operations-reader",
      display_name: "Lecteur de l’exploitation des notifications",
      description: "Diagnostique le centre de notifications sans traiter un événement ni ouvrir un canal externe.",
      status: "active",
      permissions: [NOTIFICATION_OPERATIONS_READ_PERMISSION],
      scope_types: ["global"],
    },
  ],
});

export const ADMINISTRATION_ACCESS_CATALOG = Object.freeze({
  ...ADMINISTRATION_ACCESS_CATALOG_V3,
  catalog_version: 4,
  permissions: [
    ...ADMINISTRATION_ACCESS_CATALOG_V3.permissions,
    {
      permission_id: SESSION_REVOCATION_PERMISSION,
      display_name: "Révoquer les sessions applicatives",
      description: "Fermer une session applicative active dans le périmètre global explicitement gouverné, avec justification et audit.",
      status: "active",
    },
  ],
  roles: [
    ...ADMINISTRATION_ACCESS_CATALOG_V3.roles,
    {
      role_id: "session-revocation-administrator",
      display_name: "Responsable des sessions",
      description: "Consulte les sessions actives et peut en révoquer une sans accéder à leurs secrets ni administrer les autres pouvoirs centraux.",
      status: "active",
      permissions: [SESSION_REVOCATION_PERMISSION],
      scope_types: ["global"],
    },
  ],
});

export function assertAdministrationCatalogBootstrapTarget({ database, allowBootstrap }) {
  if (allowBootstrap !== "true") throw new Error("administration catalog bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("administration catalog bootstrap can only target preproduction");
  }
}

export async function publishAdministrationAccessCatalog(repository, {
  database, allowBootstrap, correlationId = randomUUID(),
} = {}) {
  assertAdministrationCatalogBootstrapTarget({ database, allowBootstrap });
  let latest = await repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID);
  if (!latest) {
    const initial = await publishApplicationAccessCatalog({
      repository,
      principal: { applicationId: ADMIN_APPLICATION_ID, audience: ADMIN_APPLICATION_ID, correlationId },
      payload: ADMINISTRATION_ACCESS_CATALOG_V1,
      source: "administration-catalog-bootstrap",
    });
    if (![200, 201].includes(initial.status)) throw new Error(initial.body.error || "administration catalog publication failed");
    latest = await repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID);
  }
  if (latest.catalogVersion === 1) {
    const transition = await publishApplicationAccessCatalog({
      repository,
      principal: { applicationId: ADMIN_APPLICATION_ID, audience: ADMIN_APPLICATION_ID, correlationId },
      payload: ADMINISTRATION_ACCESS_CATALOG_V2,
      source: "administration-catalog-bootstrap",
    });
    if (![200, 201].includes(transition.status)) {
      throw new Error(transition.body.error || "administration catalog v2 publication failed");
    }
    latest = await repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID);
  }
  if (latest.catalogVersion === 2) {
    const transition = await publishApplicationAccessCatalog({
      repository,
      principal: { applicationId: ADMIN_APPLICATION_ID, audience: ADMIN_APPLICATION_ID, correlationId },
      payload: ADMINISTRATION_ACCESS_CATALOG_V3,
      source: "administration-catalog-bootstrap",
    });
    if (![200, 201].includes(transition.status)) {
      throw new Error(transition.body.error || "administration catalog v3 publication failed");
    }
    latest = await repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID);
  }
  if (latest.catalogVersion > ADMINISTRATION_ACCESS_CATALOG.catalog_version) {
    throw new Error("administration catalog is newer than this service");
  }
  const result = await publishApplicationAccessCatalog({
    repository,
    principal: { applicationId: ADMIN_APPLICATION_ID, audience: ADMIN_APPLICATION_ID, correlationId },
    payload: ADMINISTRATION_ACCESS_CATALOG,
    source: "administration-catalog-bootstrap",
  });
  if (![200, 201].includes(result.status)) throw new Error(result.body.error || "administration catalog publication failed");
  return { correlationId, created: result.body.created, catalogVersion: result.body.catalog_version, catalogHash: result.body.catalog_hash };
}
