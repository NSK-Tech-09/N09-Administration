import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { bootstrapIdentityLinkAdministrator } from "./identity-link-admin-bootstrap.mjs";
import { ADMIN_APPLICATION_ID, authorizeIdentityLinkAdministration } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "fred@example.test",
  displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Décision humaine explicite pour administrer les rattachements en préproduction",
};

function repositoryWithIdentity() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    subjectId: identity.identityId, justification: "Préparation du test",
  }));
  return repository;
}

test("refuse l’amorçage sans activation explicite ou hors préproduction", async () => {
  const repository = repositoryWithIdentity();
  await assert.rejects(bootstrapIdentityLinkAdministrator(repository, { ...target, allowBootstrap: "false" }), /explicitly enabled/);
  await assert.rejects(bootstrapIdentityLinkAdministrator(repository, { ...target, database: "n09_admin_prod" }), /preproduction/);
});

test("crée exactement l’application et la permission administrative auditées", async () => {
  const repository = repositoryWithIdentity();
  const before = repository.auditCount();
  const result = await bootstrapIdentityLinkAdministrator(repository, target);
  assert.deepEqual(result.created, ["application", "assignment"]);
  assert.equal(repository.auditCount(), before + 2);
  assert.equal(repository.verifyAuditChain(), true);
  assert.equal((await authorizeIdentityLinkAdministration(repository, identity.identityId)).allowed, true);
});

test("devient idempotent sans multiplier les affectations", async () => {
  const repository = repositoryWithIdentity();
  await bootstrapIdentityLinkAdministrator(repository, target);
  const auditAfterFirst = repository.auditCount();
  const second = await bootstrapIdentityLinkAdministrator(repository, target);
  assert.deepEqual(second.created, []);
  assert.equal(repository.listAssignments(identity.identityId, ADMIN_APPLICATION_ID).length, 1);
  assert.equal(repository.auditCount(), auditAfterFirst);
});
