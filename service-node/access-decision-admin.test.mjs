import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  ACCESS_DECISION_PERMISSION,
  authorizeAccessDecisionAdministration,
  revokeAccessAssignment,
} from "./access-decision-admin.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operator = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test",
  displayName: "Opérateur NSK",
  status: "active",
};
const target = {
  identityId: "70a40cd7-f2a4-4393-8021-9f806b42b41b",
  email: "target@example.test",
  displayName: "Cible NSK",
  status: "active",
};
const audit = (action, changes = {}) => createAuditEvent({
  action,
  result: "success",
  source: "access-decision-tests",
  correlationId: randomUUID(),
  justification: "Préparation reproductible du test",
  ...changes,
});

function assignment({
  assignmentId = randomUUID(),
  subjectId = target.identityId,
  applicationId = "n09-suivi-taches",
  roleId = "tasks-reader",
  permissions = ["tasks:read"],
} = {}) {
  return {
    assignmentId,
    subjectId,
    applicationId,
    roleId,
    permissions,
    scopeType: null,
    scopeId: null,
    conditions: [],
    status: "active",
    validFrom: null,
    validUntil: null,
    reason: "Accès initial contrôlé",
    decidedBy: operator.identityId,
    inheritedFromGroup: null,
    version: 1,
  };
}

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  for (const identity of [operator, target]) {
    repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  }
  for (const application of [
    { applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration", status: "active", registrationPolicy: "closed" },
    { applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches", status: "active", registrationPolicy: "closed" },
  ]) {
    repository.saveApplication(application, audit("application.registered", { applicationId: application.applicationId }));
  }
  repository.saveAssignment(assignment({
    subjectId: operator.identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "access-decision-administrator",
    permissions: [ACCESS_DECISION_PERMISSION],
  }), audit("assignment.created", { subjectId: operator.identityId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

test("accorde uniquement le pouvoir central de décision explicite", async () => {
  const repository = seededRepository();
  assert.equal((await authorizeAccessDecisionAdministration(repository, operator.identityId)).allowed, true);
  assert.equal((await authorizeAccessDecisionAdministration(repository, target.identityId)).allowed, false);
});

test("révoque une affectation avec version, opérateur et audit", async () => {
  const repository = seededRepository();
  const controlled = assignment();
  repository.saveAssignment(controlled, audit("assignment.created", {
    subjectId: controlled.subjectId,
    applicationId: controlled.applicationId,
  }));
  const before = repository.auditCount();
  const result = await revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
    correlationId: "revocation-correlation",
  });
  assert.equal(result.assignment.status, "revoked");
  assert.equal(result.assignment.version, 2);
  assert.equal(result.assignment.decidedBy, operator.identityId);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse la concurrence, une justification faible et un opérateur non autorisé", async () => {
  const repository = seededRepository();
  const controlled = assignment();
  repository.saveAssignment(controlled, audit("assignment.created", {
    subjectId: controlled.subjectId,
    applicationId: controlled.applicationId,
  }));
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 2,
    operatorIdentityId: operator.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
  }), /stale assignment version/);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "trop court",
  }), /justification/);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: target.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
  }), /not allowed/);
});

test("réserve le pouvoir de décision à une gouvernance dédiée", async () => {
  const repository = seededRepository();
  const [decisionAuthority] = repository.listAssignments(operator.identityId, ADMIN_APPLICATION_ID);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: decisionAuthority.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Passage de relais soumis à une gouvernance séparée",
  }), /dedicated governance/);
});
