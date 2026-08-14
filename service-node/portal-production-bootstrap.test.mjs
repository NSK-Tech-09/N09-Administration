import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { PORTAL_APPLICATION_ID, PORTAL_PERMISSION } from "./portal-session-broker.mjs";
import { bootstrapPortalProduction } from "./portal-production-bootstrap.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "fred@example.test", displayName: "Fred", status: "active",
};
const target = {
  database: "n09_admin_prod", allowBootstrap: "true", identityId: identity.identityId,
  justification: "Activation contrôlée du portail central sur le serveur Cloud de production",
};

function repositoryWithIdentity() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "tests",
    correlationId: crypto.randomUUID(), subjectId: identity.identityId,
    justification: "Préparation du test de production du portail",
  }));
  return repository;
}

test("enregistre le portail et le droit minimal de son propriétaire", async () => {
  const repository = repositoryWithIdentity();
  const result = await bootstrapPortalProduction(repository, target);
  assert.deepEqual(result.created, ["application", "login_policy", "assignment"]);
  assert.equal((await repository.getApplicationLoginPolicy(PORTAL_APPLICATION_ID)).requiredPermission, PORTAL_PERMISSION);
  const [assignment] = await repository.listAssignments(identity.identityId, PORTAL_APPLICATION_ID);
  assert.deepEqual(assignment.permissions, [PORTAL_PERMISSION]);
  assert.equal(repository.verifyAuditChain(), true);
  assert.deepEqual((await bootstrapPortalProduction(repository, target)).created, []);
});

test("refuse toute cible autre que la production explicitement autorisée", async () => {
  const repository = repositoryWithIdentity();
  await assert.rejects(bootstrapPortalProduction(repository, { ...target, database: "n09_admin_preprod" }), /only target production/);
  await assert.rejects(bootstrapPortalProduction(repository, { ...target, allowBootstrap: "false" }), /explicitly enabled/);
});
