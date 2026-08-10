import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { retireSyntheticPreprod } from "./retire-synthetic-preprod.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";
import { seedSyntheticPreprod, SYNTHETIC_PREPROD } from "./synthetic-preprod.mjs";

const operator = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "fred@example.test",
  displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_preprod", allowRetirement: "true", operatorIdentityId: operator.identityId,
  justification: "Fin explicite de la validation synthétique en préproduction",
};

async function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(operator, createAuditEvent({
    action: "identity.created", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    subjectId: operator.identityId, justification: "Préparation du test",
  }));
  await seedSyntheticPreprod(repository, {
    database: target.database, allowSyntheticPreprod: "true", correlationId: "seed-correlation",
  });
  return repository;
}

test("verrouille le retrait sur la préproduction et une décision explicite", async () => {
  const repository = await seededRepository();
  await assert.rejects(retireSyntheticPreprod(repository, { ...target, allowRetirement: "false" }), /explicitly enabled/);
  await assert.rejects(retireSyntheticPreprod(repository, { ...target, database: "n09_admin_prod" }), /preproduction/);
  await assert.rejects(retireSyntheticPreprod(repository, { ...target, justification: "trop court" }), /justification/);
  await assert.rejects(retireSyntheticPreprod(repository, {
    ...target, operatorIdentityId: SYNTHETIC_PREPROD.identity.identityId,
  }), /cannot retire itself/);
});

test("révoque puis archive les objets synthétiques avec audit", async () => {
  const repository = await seededRepository();
  const before = repository.auditCount();
  const result = await retireSyntheticPreprod(repository, { ...target, correlationId: "retirement-correlation" });
  assert.deepEqual(result.changed, ["assignment", "identity", "application"]);
  assert.equal(repository.auditCount(), before + 3);
  assert.equal(repository.verifyAuditChain(), true);
  assert.equal(repository.getIdentity(SYNTHETIC_PREPROD.identity.identityId).status, "archived");
  assert.equal(repository.getApplication(SYNTHETIC_PREPROD.application.applicationId).status, "retired");
  const [assignment] = repository.listAssignments(
    SYNTHETIC_PREPROD.identity.identityId, SYNTHETIC_PREPROD.application.applicationId,
  );
  assert.equal(assignment.status, "revoked");
  assert.equal(assignment.version, 2);
  assert.equal(assignment.decidedBy, operator.identityId);
});

test("devient idempotent après le retrait complet", async () => {
  const repository = await seededRepository();
  await retireSyntheticPreprod(repository, target);
  const auditAfterFirst = repository.auditCount();
  const second = await retireSyntheticPreprod(repository, target);
  assert.deepEqual(second.changed, []);
  assert.equal(repository.auditCount(), auditAfterFirst);
});

test("ne recrée rien lorsque le jeu synthétique n’a jamais existé", async () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(operator, createAuditEvent({
    action: "identity.created", result: "success", source: "tests", correlationId: crypto.randomUUID(),
    subjectId: operator.identityId, justification: "Préparation du test",
  }));
  const result = await retireSyntheticPreprod(repository, target);
  assert.deepEqual(result.changed, []);
});
