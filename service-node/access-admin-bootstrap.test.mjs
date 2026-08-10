import assert from "node:assert/strict";
import test from "node:test";
import { bootstrapAccessAdministrator } from "./access-admin-bootstrap.mjs";
import { authorizeAccessAdministration } from "./access-admin.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "fred@example.test",
  displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Décision humaine explicite pour consulter les accès en préproduction",
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
  await assert.rejects(bootstrapAccessAdministrator(repository, { ...target, allowBootstrap: "false" }), /explicitly enabled/);
  await assert.rejects(bootstrapAccessAdministrator(repository, { ...target, database: "n09_admin_prod" }), /preproduction/);
});

test("crée une permission de lecture dédiée et auditée", async () => {
  const repository = repositoryWithIdentity();
  const before = repository.auditCount();
  const result = await bootstrapAccessAdministrator(repository, target);
  assert.deepEqual(result.created, ["application", "assignment"]);
  assert.equal(repository.auditCount(), before + 2);
  assert.equal(repository.verifyAuditChain(), true);
  assert.equal((await authorizeAccessAdministration(repository, identity.identityId)).allowed, true);
});

test("reste idempotent sans fusionner les responsabilités", async () => {
  const repository = repositoryWithIdentity();
  await bootstrapAccessAdministrator(repository, target);
  const auditAfterFirst = repository.auditCount();
  const second = await bootstrapAccessAdministrator(repository, target);
  assert.deepEqual(second.created, []);
  const assignments = repository.listAssignments(identity.identityId, ADMIN_APPLICATION_ID);
  assert.equal(assignments.length, 1);
  assert.equal(assignments[0].roleId, "access-directory-reader");
  assert.equal(repository.auditCount(), auditAfterFirst);
});
