import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = { identityId: "identity-1", email: "COLLEGUE@example.test", displayName: "Collègue", status: "active" };
const application = { applicationId: "tasks", displayName: "N09 – Suivi des tâches", status: "active", registrationPolicy: "closed" };
const audit = (action, changes = {}) => createAuditEvent({
  action, result: "success", source: "tests", correlationId: "correlation-1",
  justification: "Test reproductible", ...changes,
});

function prerequisites(repository) {
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId, newValue: { status: "active" } }));
  repository.saveApplication(application, audit("application.registered", { applicationId: application.applicationId, newValue: { status: "active" } }));
}

test("normalise l’adresse et conserve la preuve", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId, newValue: { status: "active" } }));
  assert.equal(repository.getIdentity(identity.identityId).email, "collegue@example.test");
  assert.equal(repository.auditCount(), 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("l’écriture métier est annulée si son audit est invalide", () => {
  const repository = new TransactionalMemoryRepository();
  assert.throws(() => repository.saveIdentity(identity, audit("identity.created", { subjectId: "another-identity" })), /must match/);
  assert.equal(repository.getIdentity(identity.identityId), null);
  assert.equal(repository.auditCount(), 0);
});

test("une adresse déjà attribuée ne crée ni identité ni audit", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  assert.throws(() => repository.saveIdentity({ ...identity, identityId: "identity-2", email: identity.email.toLowerCase() }, audit("identity.created", { subjectId: "identity-2" })), /unique/);
  assert.equal(repository.getIdentity("identity-2"), null);
  assert.equal(repository.auditCount(), 1);
});

test("refuse une mise à jour sans état précédent", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  assert.throws(() => repository.saveIdentity({ ...identity, displayName: "Nouveau nom" }, audit("identity.updated", { subjectId: identity.identityId })), /previous value/);
  assert.equal(repository.getIdentity(identity.identityId).displayName, "Collègue");
});

test("refuse une version d’affectation périmée", () => {
  const repository = new TransactionalMemoryRepository();
  prerequisites(repository);
  const assignment = { assignmentId: "assignment-1", subjectId: "identity-1", applicationId: "tasks", roleId: "reader", permissions: ["tasks:read"], scopeType: null, scopeId: null, conditions: [], status: "active", version: 1 };
  repository.saveAssignment(assignment, audit("assignment.created", { subjectId: "identity-1", applicationId: "tasks" }));
  assert.throws(() => repository.saveAssignment({ ...assignment, status: "revoked" }, audit("assignment.revoked", { subjectId: "identity-1", applicationId: "tasks", previousValue: { status: "active" } })), /stale/);
  assert.equal(repository.listAssignments("identity-1", "tasks")[0].status, "active");
  assert.equal(repository.auditCount(), 3);
});

test("accepte la version suivante et préserve la chaîne", () => {
  const repository = new TransactionalMemoryRepository();
  prerequisites(repository);
  const assignment = { assignmentId: "assignment-1", subjectId: "identity-1", applicationId: "tasks", roleId: "reader", permissions: ["tasks:read"], scopeType: null, scopeId: null, conditions: [], status: "active", version: 1 };
  repository.saveAssignment(assignment, audit("assignment.created", { subjectId: "identity-1", applicationId: "tasks" }));
  repository.saveAssignment({ ...assignment, status: "revoked", version: 2 }, audit("assignment.revoked", { subjectId: "identity-1", applicationId: "tasks", previousValue: { status: "active" } }));
  assert.equal(repository.listAssignments("identity-1", "tasks")[0].status, "revoked");
  assert.equal(repository.verifyAuditChain(), true);
});

test("fournit un instantané trié du registre d’accès", () => {
  const repository = new TransactionalMemoryRepository();
  prerequisites(repository);
  const secondApplication = {
    applicationId: "admin", displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  };
  repository.saveApplication(secondApplication, audit("application.registered", {
    applicationId: secondApplication.applicationId,
  }));
  repository.saveAssignment({
    assignmentId: "assignment-1", subjectId: identity.identityId, applicationId: application.applicationId,
    roleId: "reader", permissions: ["tasks:read"], scopeType: null, scopeId: null,
    conditions: [], status: "active", version: 1,
  }, audit("assignment.created", { subjectId: identity.identityId, applicationId: application.applicationId }));
  assert.deepEqual(repository.listApplications().map((item) => item.applicationId), ["admin", "tasks"]);
  assert.deepEqual(repository.listAllAssignments().map((item) => item.assignmentId), ["assignment-1"]);
});

test("l’instantané d’audit ne permet pas d’altérer le journal", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  const snapshot = repository.auditSnapshot();
  snapshot[0].eventHash = "0".repeat(64);
  assert.equal(repository.verifyAuditChain(), true);
});
