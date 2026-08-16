import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  assertHistoricalLabelRepairTarget, HISTORICAL_LABEL_REPAIRS, repairHistoricalLabels,
} from "./historical-label-repair.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operator = Object.freeze({
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "f.travers@nsktech.fr",
  displayName: "Fred TRAVERS",
  status: "active",
});

function initialAudit(target) {
  return createAuditEvent({
    action: `${target.kind}.test_seeded`, result: "success", source: "tests",
    correlationId: `seed-${target.id}`,
    subjectId: target.kind === "identity" ? target.id : null,
    applicationId: target.kind === "application" ? target.id : null,
  });
}

function seed(repository, target, displayName = target.legacy) {
  if (target.kind === "identity") {
    repository.saveIdentity({
      identityId: target.id,
      email: `${target.id}@example.invalid`,
      displayName,
      status: target.id === "00000000-0000-4000-8000-000000000009" ? "archived" : "active",
    }, initialAudit(target));
  } else {
    repository.saveApplication({
      applicationId: target.id,
      displayName,
      status: target.id === "n09-synthetic" ? "retired" : "active",
      registrationPolicy: "closed",
    }, initialAudit(target));
  }
}

function seedOperator(repository) {
  repository.saveIdentity(operator, createAuditEvent({
    action: "identity.test_seeded", result: "success", source: "tests",
    correlationId: "seed-operator", subjectId: operator.identityId,
  }));
}

test("reste en lecture seule par défaut et inventorie uniquement les libellés attendus", async () => {
  const repository = new TransactionalMemoryRepository();
  HISTORICAL_LABEL_REPAIRS.forEach((target) => seed(repository, target));
  const auditCount = repository.auditCount();

  const result = await repairHistoricalLabels(repository, { database: "n09_admin_prod" });

  assert.equal(result.applied, false);
  assert.equal(result.planned.length, 4);
  assert.equal(repository.auditCount(), auditCount);
  for (const target of HISTORICAL_LABEL_REPAIRS) {
    const current = target.kind === "identity"
      ? repository.getIdentity(target.id)
      : repository.getApplication(target.id);
    assert.equal(current.displayName, target.legacy);
  }
});

test("répare les quatre libellés, conserve les états et devient idempotent", async () => {
  const repository = new TransactionalMemoryRepository();
  seedOperator(repository);
  HISTORICAL_LABEL_REPAIRS.forEach((target) => seed(repository, target));

  const input = {
    database: "n09_admin_prod",
    apply: true,
    allowRepair: "true",
    operatorIdentityId: operator.identityId,
    justification: "Correction contrôlée de quatre libellés historiques mal encodés.",
  };
  const first = await repairHistoricalLabels(repository, input);
  assert.equal(first.changed.length, 4);
  assert.equal(repository.getIdentity("00000000-0000-4000-8000-000000000009").status, "archived");
  assert.equal(repository.getApplication("n09-synthetic").status, "retired");
  for (const target of HISTORICAL_LABEL_REPAIRS) {
    const current = target.kind === "identity"
      ? repository.getIdentity(target.id)
      : repository.getApplication(target.id);
    assert.equal(current.displayName, target.canonical);
  }
  const auditCount = repository.auditCount();
  const second = await repairHistoricalLabels(repository, input);
  assert.deepEqual(second.changed, []);
  assert.equal(second.unchanged.length, 4);
  assert.equal(repository.auditCount(), auditCount);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse une valeur inattendue avant toute écriture", async () => {
  const repository = new TransactionalMemoryRepository();
  seedOperator(repository);
  HISTORICAL_LABEL_REPAIRS.forEach((target, index) => seed(
    repository, target, index === 3 ? "Libellé inconnu" : target.legacy,
  ));
  const auditCount = repository.auditCount();

  await assert.rejects(repairHistoricalLabels(repository, {
    database: "n09_admin_prod", apply: true, allowRepair: "true",
    operatorIdentityId: operator.identityId,
    justification: "Correction contrôlée de quatre libellés historiques mal encodés.",
  }), /unexpected historical label/);
  assert.equal(repository.auditCount(), auditCount);
  assert.equal(repository.getIdentity(HISTORICAL_LABEL_REPAIRS[0].id).displayName, HISTORICAL_LABEL_REPAIRS[0].legacy);
});

test("verrouille strictement une application réelle", () => {
  assert.throws(() => assertHistoricalLabelRepairTarget({ database: "n09_admin" }), /preprod or prod/);
  assert.throws(() => assertHistoricalLabelRepairTarget({
    database: "n09_admin_prod", apply: true,
  }), /not explicitly enabled/);
  assert.throws(() => assertHistoricalLabelRepairTarget({
    database: "n09_admin_prod", apply: true, allowRepair: "true",
  }), /valid operator/);
});
