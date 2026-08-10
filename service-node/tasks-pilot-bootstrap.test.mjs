import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { authorizeIdentityLinkAdministration } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";
import { bootstrapTasksPilot, TASKS_APPLICATION } from "./tasks-pilot-bootstrap.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "fred@example.test",
  displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Pilote de lecture explicitement autorisé pour N09 Suivi des tâches",
};

function repositoryWithIdentity() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    subjectId: identity.identityId, justification: "Préparation du test",
  }));
  return repository;
}

test("crée l’application pilote et le seul droit de lecture", async () => {
  const repository = repositoryWithIdentity();
  const result = await bootstrapTasksPilot(repository, target);
  assert.deepEqual(result.created, ["application", "assignment"]);
  const assignments = repository.listAssignments(identity.identityId, TASKS_APPLICATION.applicationId);
  assert.deepEqual(assignments[0].permissions, ["tasks:read"]);
  assert.equal(assignments[0].scopeType, null);
  assert.equal(repository.verifyAuditChain(), true);
  assert.equal((await authorizeIdentityLinkAdministration(repository, identity.identityId)).allowed, false);
});

test("refuse le mauvais environnement et devient idempotent", async () => {
  const repository = repositoryWithIdentity();
  await assert.rejects(bootstrapTasksPilot(repository, { ...target, database: "n09_admin_prod" }), /preproduction/);
  await bootstrapTasksPilot(repository, target);
  const auditCount = repository.auditCount();
  assert.deepEqual((await bootstrapTasksPilot(repository, target)).created, []);
  assert.equal(repository.auditCount(), auditCount);
});
