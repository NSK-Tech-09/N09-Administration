import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "./audit.mjs";
import { createAuditEvent } from "./audit.mjs";

const DEFINITION_STATUSES = new Set(["active", "planned", "deprecated"]);
const PROVISIONING_MODES = new Set(["central_identity_only", "preexisting_profile_required", "automatic"]);
const READINESS_MODES = new Set(["immediate", "application_confirmation_required"]);
const EMAIL_MATCHING_MODES = new Set(["forbidden", "verified_hint"]);
const IDENTIFIER = /^[a-z][a-z0-9:-]{1,99}$/;

export class ApplicationAccessCatalogError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function exactFields(value, allowed, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw new ApplicationAccessCatalogError(code);
  }
}

function text(value, { code, min = 1, max = 500 } = {}) {
  if (typeof value !== "string" || value.trim().length < min || value.trim().length > max) {
    throw new ApplicationAccessCatalogError(code);
  }
  return value.trim();
}

function identifier(value, code) {
  const result = text(value, { code, max: 100 });
  if (!IDENTIFIER.test(result)) throw new ApplicationAccessCatalogError(code);
  return result;
}

function unique(items, key, code) {
  if (new Set(items.map((item) => item[key])).size !== items.length) throw new ApplicationAccessCatalogError(code);
}

function identifiers(values, code) {
  if (!Array.isArray(values) || values.length === 0 || values.length > 100) throw new ApplicationAccessCatalogError(code);
  const result = values.map((value) => identifier(value, code));
  if (new Set(result).size !== result.length) throw new ApplicationAccessCatalogError(code);
  return result.sort();
}

function definition(value, idField, code) {
  exactFields(value, new Set([idField, "display_name", "description", "status"]), code);
  const status = text(value.status, { code, max: 20 });
  if (!DEFINITION_STATUSES.has(status)) throw new ApplicationAccessCatalogError(code);
  return {
    [idField]: identifier(value[idField], code),
    displayName: text(value.display_name, { code, max: 150 }),
    description: text(value.description, { code, max: 500 }),
    status,
  };
}

export function prepareApplicationAccessCatalog(payload) {
  exactFields(payload, new Set([
    "application_id", "catalog_version", "roles", "permissions", "scope_types", "provisioning",
  ]), "invalid_catalog");
  if (!Number.isInteger(payload.catalog_version) || payload.catalog_version < 1 || payload.catalog_version > 4_294_967_295) {
    throw new ApplicationAccessCatalogError("invalid_catalog_version");
  }
  if (!Array.isArray(payload.permissions) || payload.permissions.length === 0 || payload.permissions.length > 200) {
    throw new ApplicationAccessCatalogError("invalid_permissions");
  }
  const permissions = payload.permissions.map((item) => definition(item, "permission_id", "invalid_permission"));
  unique(permissions, "permission_id", "duplicate_permission");

  if (!Array.isArray(payload.scope_types) || payload.scope_types.length === 0 || payload.scope_types.length > 100) {
    throw new ApplicationAccessCatalogError("invalid_scope_types");
  }
  const scopeTypes = payload.scope_types.map((item) => definition(item, "scope_type_id", "invalid_scope_type"));
  unique(scopeTypes, "scope_type_id", "duplicate_scope_type");

  if (!Array.isArray(payload.roles) || payload.roles.length === 0 || payload.roles.length > 100) {
    throw new ApplicationAccessCatalogError("invalid_roles");
  }
  const permissionById = new Map(permissions.map((item) => [item.permission_id, item]));
  const scopeTypeById = new Map(scopeTypes.map((item) => [item.scope_type_id, item]));
  const roles = payload.roles.map((item) => {
    exactFields(item, new Set([
      "role_id", "display_name", "description", "status", "permissions", "scope_types",
    ]), "invalid_role");
    const role = {
      role_id: identifier(item.role_id, "invalid_role"),
      displayName: text(item.display_name, { code: "invalid_role", max: 150 }),
      description: text(item.description, { code: "invalid_role", max: 500 }),
      status: text(item.status, { code: "invalid_role", max: 20 }),
      permissions: identifiers(item.permissions, "invalid_role_permissions"),
      scopeTypes: identifiers(item.scope_types, "invalid_role_scope_types"),
    };
    if (!DEFINITION_STATUSES.has(role.status)) throw new ApplicationAccessCatalogError("invalid_role");
    if (role.permissions.some((permissionId) => !permissionById.has(permissionId))) {
      throw new ApplicationAccessCatalogError("unknown_role_permission");
    }
    if (role.scopeTypes.some((scopeTypeId) => !scopeTypeById.has(scopeTypeId))) {
      throw new ApplicationAccessCatalogError("unknown_role_scope_type");
    }
    if (role.status === "active" && role.permissions.some((permissionId) => permissionById.get(permissionId).status !== "active")) {
      throw new ApplicationAccessCatalogError("active_role_uses_inactive_permission");
    }
    if (role.status === "active" && role.scopeTypes.some((scopeTypeId) => scopeTypeById.get(scopeTypeId).status !== "active")) {
      throw new ApplicationAccessCatalogError("active_role_uses_inactive_scope_type");
    }
    return role;
  });
  unique(roles, "role_id", "duplicate_role");

  exactFields(payload.provisioning, new Set([
    "mode", "identity_key", "readiness", "automatic_profile_creation", "email_matching", "requirements",
  ]), "invalid_provisioning");
  const mode = text(payload.provisioning.mode, { code: "invalid_provisioning", max: 50 });
  const readiness = text(payload.provisioning.readiness, { code: "invalid_provisioning", max: 50 });
  const emailMatching = text(payload.provisioning.email_matching, { code: "invalid_provisioning", max: 30 });
  if (!PROVISIONING_MODES.has(mode) || !READINESS_MODES.has(readiness) || !EMAIL_MATCHING_MODES.has(emailMatching) ||
      payload.provisioning.identity_key !== "identity_id" || typeof payload.provisioning.automatic_profile_creation !== "boolean") {
    throw new ApplicationAccessCatalogError("invalid_provisioning");
  }
  if ((mode === "automatic") !== payload.provisioning.automatic_profile_creation) {
    throw new ApplicationAccessCatalogError("inconsistent_provisioning_mode");
  }
  if (mode === "preexisting_profile_required" && readiness !== "application_confirmation_required") {
    throw new ApplicationAccessCatalogError("inconsistent_provisioning_readiness");
  }
  if (!Array.isArray(payload.provisioning.requirements) || payload.provisioning.requirements.length > 50) {
    throw new ApplicationAccessCatalogError("invalid_provisioning_requirements");
  }
  const requirements = payload.provisioning.requirements.map((item) => {
    exactFields(item, new Set(["requirement_id", "display_name", "description"]), "invalid_provisioning_requirement");
    return {
      requirement_id: identifier(item.requirement_id, "invalid_provisioning_requirement"),
      displayName: text(item.display_name, { code: "invalid_provisioning_requirement", max: 150 }),
      description: text(item.description, { code: "invalid_provisioning_requirement", max: 500 }),
    };
  });
  unique(requirements, "requirement_id", "duplicate_provisioning_requirement");
  if (mode === "preexisting_profile_required" && requirements.length === 0) {
    throw new ApplicationAccessCatalogError("missing_provisioning_requirement");
  }

  return {
    applicationId: identifier(payload.application_id, "invalid_application_id"),
    catalogVersion: payload.catalog_version,
    roles: roles.sort((left, right) => left.role_id.localeCompare(right.role_id)),
    permissions: permissions.sort((left, right) => left.permission_id.localeCompare(right.permission_id)),
    scopeTypes: scopeTypes.sort((left, right) => left.scope_type_id.localeCompare(right.scope_type_id)),
    provisioning: {
      mode, identityKey: "identity_id", readiness,
      automaticProfileCreation: payload.provisioning.automatic_profile_creation,
      emailMatching, requirements: requirements.sort((left, right) => left.requirement_id.localeCompare(right.requirement_id)),
    },
  };
}

export function applicationAccessCatalogHash(catalog) {
  return createHash("sha256").update(canonicalJson(catalog), "utf8").digest("hex");
}

export function assertCompatibleCatalogEvolution(previous, next) {
  if (!previous) {
    if (next.catalogVersion !== 1) throw new ApplicationAccessCatalogError("catalog_version_sequence", 409);
    return;
  }
  if (next.catalogVersion !== previous.catalogVersion + 1) {
    throw new ApplicationAccessCatalogError("catalog_version_sequence", 409);
  }
  for (const [field, idField] of [["roles", "role_id"], ["permissions", "permission_id"], ["scopeTypes", "scope_type_id"]]) {
    const nextIds = new Set(next[field].map((item) => item[idField]));
    if (previous[field].some((item) => !nextIds.has(item[idField]))) {
      throw new ApplicationAccessCatalogError("catalog_identifier_removed", 409);
    }
  }
}

export async function publishApplicationAccessCatalog({ repository, principal, payload, source = "application-catalog-api" }) {
  if (!principal) return { status: 401, body: { error: "authentication_required" } };
  if (principal.audience !== principal.applicationId) return { status: 403, body: { error: "invalid_audience" } };
  let catalog;
  try { catalog = prepareApplicationAccessCatalog(payload); }
  catch (error) {
    if (error instanceof ApplicationAccessCatalogError) return { status: error.status, body: { error: error.code } };
    throw error;
  }
  if (catalog.applicationId !== principal.applicationId) {
    return { status: 403, body: { error: "application_boundary_violation" } };
  }
  const application = await repository.getApplication(catalog.applicationId);
  if (!application) return { status: 404, body: { error: "application_not_found" } };
  if (application.status === "retired") return { status: 409, body: { error: "application_retired" } };
  const catalogHash = applicationAccessCatalogHash(catalog);
  try {
    const result = await repository.publishApplicationAccessCatalog(catalog, createAuditEvent({
      action: "application.access_catalog_published", result: "success", source,
      correlationId: principal.correlationId || randomUUID(), applicationId: catalog.applicationId,
      newValue: {
        catalog_version: catalog.catalogVersion, catalog_hash: catalogHash,
        roles: catalog.roles.map((item) => item.role_id),
        permissions: catalog.permissions.map((item) => item.permission_id),
        scope_types: catalog.scopeTypes.map((item) => item.scope_type_id),
        provisioning_mode: catalog.provisioning.mode,
      },
    }));
    return {
      status: result.created ? 201 : 200,
      body: { application_id: catalog.applicationId, catalog_version: catalog.catalogVersion, catalog_hash: catalogHash, created: result.created },
    };
  } catch (error) {
    if (error instanceof ApplicationAccessCatalogError) return { status: error.status, body: { error: error.code } };
    throw error;
  }
}
