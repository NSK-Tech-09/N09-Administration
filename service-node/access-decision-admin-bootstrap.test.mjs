import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { bootstrapAccessDecisionAdministrator } from "./access-decision-admin-bootstrap.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "admin@example.test",
  displayName: "Admin NSK",
  status: "active",
};
const target = {
  database: "n09_admin_preprod",
  allowBootstrap: "true",
  identityId: identity.identityId,
  justification: "Autorisation explicite de décider les révocations centrales",
};
const audit = (action, changes = {}) => createAuditEvent({
  action,
  result: "success",
  source: "bootstrap-tests",
  correlationId: randomUUID(),
  justification: "Préparation reproductible du test",
  ...changes,
});

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID,
    displayName: "N09 – Administration",
    status: "active",
    registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

test("verrouille l’amorçage sur une préproduction explicitement autorisée", async () => {
  const repository = seededRepository();
  await assert.rejects(bootstrapAccessDecisionAdministrator(repository, {
    ...target,
    allowBootstrap: "false",
  }), /explicitly enabled/);
  await assert.rejects(bootstrapAccessDecisionAdministrator(repository, {
    ...target,
    database: "n09_admin_prod",
  }), /preproduction/);
});

test("crée le pouvoir exact avec audit puis devient idempotent", async () => {
  const repository = seededRepository();
  const before = repository.auditCount();
  const first = await bootstrapAccessDecisionAdministrator(repository, target);
  assert.deepEqual(first.created, ["assignment"]);
  const [created] = repository.listAssignments(identity.identityId, ADMIN_APPLICATION_ID);
  assert.deepEqual(created.permissions, [ACCESS_DECISION_PERMISSION]);
  assert.equal(created.roleId, "access-decision-administrator");
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);

  const second = await bootstrapAccessDecisionAdministrator(repository, target);
  assert.deepEqual(second.created, []);
  assert.equal(repository.auditCount(), before + 1);
});
