import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  prepareApplicationAccessCatalog, publishApplicationAccessCatalog,
} from "./application-access-catalog.mjs";
import { createAuditEvent } from "./audit.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const application = {
  applicationId: "tasks", displayName: "Tâches", status: "active", registrationPolicy: "closed",
};
const principal = { applicationId: "tasks", audience: "tasks", correlationId: randomUUID() };
const catalog = {
  application_id: "tasks", catalog_version: 1,
  permissions: [
    { permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tâches autorisées.", status: "active" },
    { permission_id: "tasks:write", display_name: "Écrire", description: "Modifier les tâches autorisées.", status: "planned" },
  ],
  scope_types: [
    { scope_type_id: "global", display_name: "Global", description: "Toute l’application.", status: "active" },
    { scope_type_id: "site", display_name: "Site", description: "Un site métier.", status: "planned" },
  ],
  roles: [
    { role_id: "tasks-pilot-reader", display_name: "Lecteur pilote", description: "Lecture pilote globale.", status: "active", permissions: ["tasks:read"], scope_types: ["global"] },
    { role_id: "tasks-writer", display_name: "Contributeur", description: "Écriture ciblée future.", status: "planned", permissions: ["tasks:read", "tasks:write"], scope_types: ["site"] },
  ],
  provisioning: {
    mode: "preexisting_profile_required", identity_key: "identity_id",
    readiness: "application_confirmation_required", automatic_profile_creation: false,
    email_matching: "forbidden",
    requirements: [
      { requirement_id: "local-profile", display_name: "Profil local", description: "Le profil local doit exister avant l’octroi." },
    ],
  },
};

const audit = (action, changes = {}) => createAuditEvent({
  action, result: "success", source: "catalog-tests", correlationId: randomUUID(),
  justification: "Test du catalogue applicatif", ...changes,
});

function seededRepository({ withAssignment = false } = {}) {
  const repository = new TransactionalMemoryRepository();
  repository.saveApplication(application, audit("application.registered", { applicationId: application.applicationId }));
  if (withAssignment) {
    repository.saveIdentity({ identityId: "identity-1", email: "test@example.invalid", displayName: "Test", status: "active" },
      audit("identity.created", { subjectId: "identity-1" }));
    repository.saveAssignment({
      assignmentId: randomUUID(), subjectId: "identity-1", applicationId: "tasks",
      roleId: "unknown-active-role", permissions: ["tasks:read"], scopeType: null, scopeId: null,
      conditions: [], status: "active", validFrom: null, validUntil: null, reason: "Test",
      decidedBy: null, inheritedFromGroup: null, version: 1,
    }, audit("assignment.created", { subjectId: "identity-1", applicationId: "tasks" }));
  }
  return repository;
}

test("normalise un catalogue versionné et refuse les références fictives", () => {
  const prepared = prepareApplicationAccessCatalog(catalog);
  assert.equal(prepared.catalogVersion, 1);
  assert.deepEqual(prepared.roles[0].permissions, ["tasks:read"]);
  assert.throws(() => prepareApplicationAccessCatalog({
    ...catalog,
    roles: [{ ...catalog.roles[0], permissions: ["tasks:unknown"] }],
  }), /unknown_role_permission/);
  assert.throws(() => prepareApplicationAccessCatalog({
    ...catalog,
    roles: [{ ...catalog.roles[1], status: "active" }],
  }), /active_role_uses_inactive_permission/);
});

test("publie une version auditée puis devient strictement idempotent", async () => {
  const repository = seededRepository();
  const before = repository.auditCount();
  const created = await publishApplicationAccessCatalog({ repository, principal, payload: catalog });
  assert.equal(created.status, 201);
  assert.equal(created.body.created, true);
  assert.match(created.body.catalog_hash, /^[0-9a-f]{64}$/);
  assert.equal(repository.auditCount(), before + 1);
  const replay = await publishApplicationAccessCatalog({ repository, principal, payload: catalog });
  assert.equal(replay.status, 200);
  assert.equal(replay.body.created, false);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.getLatestApplicationAccessCatalog("tasks").catalogVersion, 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("isole l’application et bloque version ou disparition incompatible", async () => {
  const repository = seededRepository();
  assert.equal((await publishApplicationAccessCatalog({
    repository, principal: { applicationId: "other", audience: "other" }, payload: catalog,
  })).status, 403);
  assert.equal((await publishApplicationAccessCatalog({ repository, principal, payload: catalog })).status, 201);
  assert.equal((await publishApplicationAccessCatalog({
    repository, principal, payload: {
      ...catalog,
      permissions: [{ ...catalog.permissions[0], display_name: "Autre libellé" }, catalog.permissions[1]],
    },
  })).body.error, "catalog_version_conflict");
  assert.equal((await publishApplicationAccessCatalog({
    repository, principal, payload: {
      ...catalog, catalog_version: 2,
      roles: [catalog.roles[0]], permissions: [catalog.permissions[0]], scope_types: [catalog.scope_types[0]],
    },
  })).body.error, "catalog_identifier_removed");
});

test("refuse un catalogue qui rend une affectation active ininterprétable", async () => {
  const repository = seededRepository({ withAssignment: true });
  const result = await publishApplicationAccessCatalog({ repository, principal, payload: catalog });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, "catalog_excludes_active_assignment");
  assert.equal(repository.getLatestApplicationAccessCatalog("tasks"), null);
});
