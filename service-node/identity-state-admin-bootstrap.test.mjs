import assert from "node:assert/strict";
import test from "node:test";
import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  bootstrapIdentityDisablementAdministrator,
  bootstrapIdentityReactivationAdministrator,
  bootstrapIdentitySuspensionAdministrator,
} from "./identity-state-admin-bootstrap.mjs";
import {
  authorizeIdentityDisablementAdministration,
  authorizeIdentityReactivationAdministration,
  authorizeIdentitySuspensionAdministration,
} from "./identity-state-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test", displayName: "Opérateur", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Décision humaine explicite pour administrer les suspensions en préproduction",
};

function repositoryWithAdministration() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    subjectId: identity.identityId, justification: "Préparation du test",
  }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    applicationId: ADMIN_APPLICATION_ID, justification: "Préparation du test",
  }));
  return repository;
}

test("refuse l’amorçage sans activation explicite ou hors préproduction", async () => {
  const repository = repositoryWithAdministration();
  await assert.rejects(bootstrapIdentitySuspensionAdministrator(repository, {
    ...target, allowBootstrap: "false",
  }), /explicitly enabled/);
  await assert.rejects(bootstrapIdentitySuspensionAdministrator(repository, {
    ...target, database: "n09_admin_prod",
  }), /preproduction/);
  await assert.rejects(bootstrapIdentityReactivationAdministrator(repository, {
    ...target, allowBootstrap: "false",
  }), /explicitly enabled/);
  await assert.rejects(bootstrapIdentityDisablementAdministrator(repository, {
    ...target, allowBootstrap: "false",
  }), /explicitly enabled/);
});

test("crée les trois pouvoirs par trois amorçages explicites séparés et reste idempotent", async () => {
  const repository = repositoryWithAdministration();
  await publishAdministrationAccessCatalog(repository, { database: "n09_admin_preprod", allowBootstrap: "true" });
  const before = repository.auditCount();
  assert.deepEqual((await bootstrapIdentitySuspensionAdministrator(repository, target)).created, ["assignment"]);
  assert.equal((await authorizeIdentitySuspensionAdministration(repository, identity.identityId)).allowed, true);
  assert.equal((await authorizeIdentityReactivationAdministration(repository, identity.identityId)).allowed, false);
  assert.deepEqual((await bootstrapIdentityReactivationAdministrator(repository, target)).created, ["assignment"]);
  assert.equal((await authorizeIdentityReactivationAdministration(repository, identity.identityId)).allowed, true);
  assert.equal((await authorizeIdentityDisablementAdministration(repository, identity.identityId)).allowed, false);
  assert.deepEqual((await bootstrapIdentityDisablementAdministrator(repository, target)).created, ["assignment"]);
  assert.equal((await authorizeIdentityDisablementAdministration(repository, identity.identityId)).allowed, true);
  assert.deepEqual((await bootstrapIdentitySuspensionAdministrator(repository, target)).created, []);
  assert.deepEqual((await bootstrapIdentityReactivationAdministrator(repository, target)).created, []);
  assert.deepEqual((await bootstrapIdentityDisablementAdministrator(repository, target)).created, []);
  assert.equal(repository.auditCount(), before + 3);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse l’affectation tant que le catalogue v6 n’est pas publié", async () => {
  await assert.rejects(bootstrapIdentityReactivationAdministrator(repositoryWithAdministration(), target), /catalog v6/);
});

test("refuse la désactivation tant que le catalogue v7 n’est pas publié", async () => {
  await assert.rejects(bootstrapIdentityDisablementAdministrator(repositoryWithAdministration(), target), /catalog v7/);
});
