import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  ADMINISTRATION_ACCESS_CATALOG, publishAdministrationAccessCatalog,
} from "./administration-access-catalog.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

function repositoryWithAdministration() {
  const repository = new TransactionalMemoryRepository();
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "catalog-tests",
    correlationId: randomUUID(), applicationId: ADMIN_APPLICATION_ID,
  }));
  return repository;
}

test("décrit les huit pouvoirs séparés et borne l’octroi aux rôles publiés", () => {
  assert.deepEqual(ADMINISTRATION_ACCESS_CATALOG.roles.map((item) => item.role_id).sort(), [
    "access-decision-administrator", "access-directory-reader", "identity-disablement-administrator",
    "identity-link-administrator", "identity-reactivation-administrator", "identity-suspension-administrator",
    "notification-operations-reader",
    "session-revocation-administrator",
  ]);
  assert.equal(ADMINISTRATION_ACCESS_CATALOG.provisioning.mode, "central_identity_only");
  assert.equal(ADMINISTRATION_ACCESS_CATALOG.catalog_version, 7);
  assert.deepEqual(ADMINISTRATION_ACCESS_CATALOG.roles
    .find((item) => item.role_id === "session-revocation-administrator").permissions,
  ["administration:sessions:revoke"]);
  assert.deepEqual(ADMINISTRATION_ACCESS_CATALOG.roles
    .find((item) => item.role_id === "identity-suspension-administrator").permissions,
  ["administration:identities:suspend"]);
  assert.deepEqual(ADMINISTRATION_ACCESS_CATALOG.roles
    .find((item) => item.role_id === "identity-reactivation-administrator").permissions,
  ["administration:identities:reactivate"]);
  assert.deepEqual(ADMINISTRATION_ACCESS_CATALOG.roles
    .find((item) => item.role_id === "identity-disablement-administrator").permissions,
  ["administration:identities:disable"]);
  assert.match(ADMINISTRATION_ACCESS_CATALOG.permissions
    .find((item) => item.permission_id === "administration:access:decide").description, /Accorder un rôle applicatif actif/);
});

test("borne la publication à la préproduction et la rend idempotente", async () => {
  const repository = repositoryWithAdministration();
  await assert.rejects(publishAdministrationAccessCatalog(repository, {
    database: "n09_admin_prod", allowBootstrap: "true",
  }), /preproduction/);
  const first = await publishAdministrationAccessCatalog(repository, {
    database: "n09_admin_preprod", allowBootstrap: "true",
  });
  const second = await publishAdministrationAccessCatalog(repository, {
    database: "n09_admin_preprod", allowBootstrap: "true",
  });
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(repository.getLatestApplicationAccessCatalog(ADMIN_APPLICATION_ID).catalogVersion, 7);
  assert.equal(repository.verifyAuditChain(), true);
});
