import { randomUUID } from "node:crypto";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { ADMIN_APPLICATION_ID, LINK_DECISION_PERMISSION } from "./identity-link-admin.mjs";

export const ADMINISTRATION_ACCESS_CATALOG = Object.freeze({
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
  const result = await publishApplicationAccessCatalog({
    repository,
    principal: { applicationId: ADMIN_APPLICATION_ID, audience: ADMIN_APPLICATION_ID, correlationId },
    payload: ADMINISTRATION_ACCESS_CATALOG,
    source: "administration-catalog-bootstrap",
  });
  if (![200, 201].includes(result.status)) throw new Error(result.body.error || "administration catalog publication failed");
  return { correlationId, created: result.body.created, catalogVersion: result.body.catalog_version, catalogHash: result.body.catalog_hash };
}
