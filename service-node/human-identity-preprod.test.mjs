import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createHumanIdentityPreprod } from "./human-identity-preprod.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operator = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test",
  displayName: "Opérateur",
  status: "active",
};
const target = {
  database: "n09_admin_preprod",
  allowCreation: "true",
  operatorIdentityId: operator.identityId,
  email: "travers.fred.09@gmail.com",
  displayName: "Fred TRAVERS — Recette",
  justification: "Création contrôlée de la seconde identité humaine de recette",
  identityId: "70a40cd7-f2a4-4393-8021-9f806b42b41b",
  correlationId: "human-identity-correlation",
};

function repositoryWithOperator(status = "active") {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({ ...operator, status }, createAuditEvent({
    action: "identity.created",
    result: "success",
    source: "tests",
    correlationId: crypto.randomUUID(),
    subjectId: operator.identityId,
    justification: "Préparation du test de création humaine",
  }));
  return repository;
}

test("verrouille la création sur la préproduction et une décision explicite", async () => {
  const repository = repositoryWithOperator();
  await assert.rejects(createHumanIdentityPreprod(repository, { ...target, allowCreation: "false" }), /explicitly enabled/);
  await assert.rejects(createHumanIdentityPreprod(repository, { ...target, database: "n09_admin" }), /preproduction/);
  await assert.rejects(createHumanIdentityPreprod(repository, { ...target, email: "invalide" }), /valid human email/);
  await assert.rejects(createHumanIdentityPreprod(repository, { ...target, justification: "trop court" }), /justification/);
});

test("exige un opérateur actif", async () => {
  await assert.rejects(createHumanIdentityPreprod(new TransactionalMemoryRepository(), target), /operator identity/);
  await assert.rejects(createHumanIdentityPreprod(repositoryWithOperator("suspended"), target), /operator identity/);
});

test("crée une identité active sans aucun droit et avec audit", async () => {
  const repository = repositoryWithOperator();
  const before = repository.auditCount();
  const result = await createHumanIdentityPreprod(repository, target);
  assert.equal(result.created, true);
  assert.equal(result.identityId, target.identityId);
  assert.deepEqual(repository.getIdentity(target.identityId), {
    identityId: target.identityId,
    email: target.email,
    displayName: target.displayName,
    status: "active",
  });
  assert.equal(repository.listAllAssignments().filter((item) => item.subjectId === target.identityId).length, 0);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("est idempotent pour la même définition contrôlée", async () => {
  const repository = repositoryWithOperator();
  await createHumanIdentityPreprod(repository, target);
  const auditAfterFirst = repository.auditCount();
  const second = await createHumanIdentityPreprod(repository, { ...target, identityId: crypto.randomUUID() });
  assert.equal(second.created, false);
  assert.equal(second.identityId, target.identityId);
  assert.equal(repository.auditCount(), auditAfterFirst);
});

test("refuse une collision de courriel ou d'identifiant", async () => {
  const repository = repositoryWithOperator();
  await createHumanIdentityPreprod(repository, target);
  await assert.rejects(createHumanIdentityPreprod(repository, {
    ...target,
    displayName: "Autre personne",
    identityId: crypto.randomUUID(),
  }), /different controlled definition/);
  await assert.rejects(createHumanIdentityPreprod(repository, {
    ...target,
    email: "autre@nsktech.fr",
  }), /target identity id already exists/);
});
