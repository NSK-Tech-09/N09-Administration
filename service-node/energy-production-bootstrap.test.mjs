import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  bootstrapEnergyProduction, ENERGY_APPLICATION, ENERGY_PERMISSIONS, ENERGY_PRODUCTION_REDIRECT_URI,
} from "./energy-production-bootstrap.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "fred@example.test",
  displayName: "Fred",
  status: "active",
};
const target = {
  database: "n09_admin_prod",
  allowBootstrap: "true",
  identityId: identity.identityId,
  justification: "Activation contrôlée de N09 Énergie sur le serveur Cloud de production",
  redirectUri: ENERGY_PRODUCTION_REDIRECT_URI,
};

function repositoryWithIdentity() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "tests",
    correlationId: crypto.randomUUID(), subjectId: identity.identityId,
    justification: "Préparation du test de production Énergie",
  }));
  return repository;
}

test("enregistre Énergie, son retour exact et les droits du propriétaire", async () => {
  const repository = repositoryWithIdentity();
  const result = await bootstrapEnergyProduction(repository, target);
  assert.deepEqual(result.created, ["application", "redirect_uri", "login_policy", "assignment"]);
  assert.deepEqual(await repository.getApplication(ENERGY_APPLICATION.applicationId), ENERGY_APPLICATION);
  assert.equal((await repository.getApplicationLoginPolicy(ENERGY_APPLICATION.applicationId)).requiredPermission, "energy:read");
  const [assignment] = await repository.listAssignments(identity.identityId, ENERGY_APPLICATION.applicationId);
  assert.deepEqual(assignment.permissions, [...ENERGY_PERMISSIONS]);
  assert.equal(assignment.scopeType, null);
  assert.equal(repository.verifyAuditChain(), true);
});

test("est idempotent et refuse toute cible moins précise", async () => {
  const repository = repositoryWithIdentity();
  await bootstrapEnergyProduction(repository, target);
  const auditCount = repository.auditCount();
  assert.deepEqual((await bootstrapEnergyProduction(repository, target)).created, []);
  assert.equal(repository.auditCount(), auditCount);
  await assert.rejects(bootstrapEnergyProduction(repository, { ...target, database: "n09_admin_preprod" }), /only target production/);
  await assert.rejects(bootstrapEnergyProduction(repository, {
    ...target, redirectUri: "https://attacker.example.test/auth/nsk/callback",
  }), /controlled production callback/);
});

test("ne remplace pas silencieusement une décision d'accès existante", async () => {
  const repository = repositoryWithIdentity();
  await bootstrapEnergyProduction(repository, target);
  const [current] = await repository.listAssignments(identity.identityId, ENERGY_APPLICATION.applicationId);
  await repository.saveAssignment({
    ...current,
    permissions: ["energy:read"],
    version: current.version + 1,
  }, createAuditEvent({
    action: "assignment.changed", result: "success", source: "tests",
    correlationId: crypto.randomUUID(), subjectId: identity.identityId,
    applicationId: ENERGY_APPLICATION.applicationId, roleId: current.roleId,
    justification: "Simulation d'une décision concurrente explicite",
    previousValue: { permissions: current.permissions, version: current.version },
    newValue: { permissions: ["energy:read"], version: current.version + 1 },
  }));
  await assert.rejects(bootstrapEnergyProduction(repository, target), /conflicts/);
});
