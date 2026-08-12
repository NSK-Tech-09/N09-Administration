import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { bootstrapNotificationOperationsReader } from "./notification-operations-admin-bootstrap.mjs";
import { authorizeNotificationOperationsAdministration } from "./notification-operations-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "fred@example.test",
  displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Décision humaine explicite pour diagnostiquer les notifications en préproduction",
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
  await assert.rejects(bootstrapNotificationOperationsReader(repository, {
    ...target, allowBootstrap: "false",
  }), /explicitly enabled/);
  await assert.rejects(bootstrapNotificationOperationsReader(repository, {
    ...target, database: "n09_admin_prod",
  }), /preproduction/);
});

test("crée un pouvoir séparé, audité et idempotent", async () => {
  const repository = repositoryWithAdministration();
  const before = repository.auditCount();
  const first = await bootstrapNotificationOperationsReader(repository, target);
  assert.deepEqual(first.created, ["assignment"]);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal((await authorizeNotificationOperationsAdministration(repository, identity.identityId)).allowed, true);
  const second = await bootstrapNotificationOperationsReader(repository, target);
  assert.deepEqual(second.created, []);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);
});
