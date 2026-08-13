import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { bootstrapOperatorSessionAdministrator } from "./operator-session-admin-bootstrap.mjs";
import { authorizeSessionRevocationAdministration } from "./operator-session-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test", displayName: "Opérateur", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Décision humaine explicite pour administrer les sessions de préproduction",
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
  await assert.rejects(bootstrapOperatorSessionAdministrator(repository, {
    ...target, allowBootstrap: "false",
  }), /explicitly enabled/);
  await assert.rejects(bootstrapOperatorSessionAdministrator(repository, {
    ...target, database: "n09_admin_prod",
  }), /preproduction/);
});

test("crée un pouvoir séparé, global, audité et idempotent", async () => {
  const repository = repositoryWithAdministration();
  await publishAdministrationAccessCatalog(repository, {
    database: "n09_admin_preprod", allowBootstrap: "true",
  });
  const before = repository.auditCount();
  const first = await bootstrapOperatorSessionAdministrator(repository, target);
  assert.deepEqual(first.created, ["assignment"]);
  const assignment = repository.listAssignments(identity.identityId, ADMIN_APPLICATION_ID).at(-1);
  assert.equal(assignment.scopeType, null);
  assert.equal((await authorizeSessionRevocationAdministration(repository, identity.identityId)).allowed, true);
  const second = await bootstrapOperatorSessionAdministrator(repository, target);
  assert.deepEqual(second.created, []);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse l’affectation tant que le catalogue version 4 n’est pas publié", async () => {
  await assert.rejects(bootstrapOperatorSessionAdministrator(repositoryWithAdministration(), target),
    /catalog v4/);
});
