import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  createApplicationSession, createApplicationSessionAuditEvent,
  revokeApplicationSession, touchApplicationSession,
} from "./application-session.mjs";
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

function applicationSession(repository) {
  prerequisites(repository);
  return createApplicationSession({
    identityId: identity.identityId, applicationId: application.applicationId,
    idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: new Date("2026-08-13T04:00:00Z"), now: new Date("2026-08-13T04:01:00Z"),
    randomUuidImpl: () => "00000000-0000-4000-8000-000000000044",
    randomBytesImpl: () => Buffer.alloc(32, 9),
  });
}

test("persiste la session et son audit de création dans une seule transaction mémoire", () => {
  const repository = new TransactionalMemoryRepository();
  const { record } = applicationSession(repository);
  const event = createApplicationSessionAuditEvent({
    record, action: "application_session.created", correlationId: "session-created",
  });
  repository.saveApplicationSession(record, event);
  assert.deepEqual(repository.getApplicationSession(record.sessionId), record);
  assert.deepEqual(repository.listApplicationSessions(identity.identityId), [record]);
  assert.equal(repository.auditCount(), 3);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse un nouvel enregistrement qui ne serait pas actif en version initiale", () => {
  const repository = new TransactionalMemoryRepository();
  const { record } = applicationSession(repository);
  const invalid = { ...record, version: 2 };
  assert.throws(() => repository.saveApplicationSession(invalid, createApplicationSessionAuditEvent({
    record: invalid, action: "application_session.created", correlationId: "invalid-session",
  })), /invalid new/);
  assert.equal(repository.getApplicationSession(record.sessionId), null);
  assert.equal(repository.auditCount(), 2);
});

test("actualise l’activité avec concurrence optimiste sans créer un audit par lecture", () => {
  const repository = new TransactionalMemoryRepository();
  const { record } = applicationSession(repository);
  repository.saveApplicationSession(record, createApplicationSessionAuditEvent({
    record, action: "application_session.created", correlationId: "session-created",
  }));
  const touched = touchApplicationSession(record, { now: new Date("2026-08-13T04:30:00Z") });
  repository.touchApplicationSession(touched, 1);
  assert.equal(repository.getApplicationSession(record.sessionId).version, 2);
  assert.equal(repository.auditCount(), 3);
  assert.throws(() => repository.touchApplicationSession(touched, 1), /stale/);
  assert.throws(() => repository.touchApplicationSession({
    ...repository.getApplicationSession(record.sessionId),
    revokedAt: "2026-08-13T04:31:00.000Z", version: 3,
    lastSeenAt: "2026-08-13T04:31:00.000Z", idleExpiresAt: "2026-08-13T05:31:00.000Z",
  }, 2), /revocation cannot change/);
});

test("révoque avec audit atomique et refuse un audit contenant la référence complète", () => {
  const repository = new TransactionalMemoryRepository();
  const { record } = applicationSession(repository);
  repository.saveApplicationSession(record, createApplicationSessionAuditEvent({
    record, action: "application_session.created", correlationId: "session-created",
  }));
  const revoked = revokeApplicationSession(record, {
    revokedByIdentityId: identity.identityId, reason: "Déconnexion distante demandée",
    now: new Date("2026-08-13T04:20:00Z"),
  });
  const mismatchedActor = createApplicationSessionAuditEvent({
    record: revoked, action: "application_session.revoked", correlationId: "wrong-actor",
  });
  assert.throws(() => repository.revokeApplicationSession(revoked, 1, mismatchedActor), /actor must match/);
  assert.equal(repository.getApplicationSession(record.sessionId).revokedAt, null);
  repository.revokeApplicationSession(revoked, 1, createApplicationSessionAuditEvent({
    record: revoked, action: "application_session.revoked", actorId: identity.identityId,
    correlationId: "session-revoked",
  }));
  assert.equal(repository.getApplicationSession(record.sessionId).revokedAt, "2026-08-13T04:20:00.000Z");
  assert.equal(repository.auditCount(), 4);

  const second = createApplicationSession({
    identityId: identity.identityId, applicationId: application.applicationId,
    idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    now: new Date("2026-08-13T05:00:00Z"), authenticatedAt: new Date("2026-08-13T05:00:00Z"),
    randomUuidImpl: () => "00000000-0000-4000-8000-000000000045",
    randomBytesImpl: () => Buffer.alloc(32, 10),
  }).record;
  const leakingAudit = createAuditEvent({
    action: "application_session.created", result: "success", source: "tests",
    correlationId: "leaking-audit", subjectId: second.identityId, applicationId: second.applicationId,
    newValue: { reference: second.sessionId },
  });
  assert.throws(() => repository.saveApplicationSession(second, leakingAudit), /must not contain/);
  assert.equal(repository.getApplicationSession(second.sessionId), null);
});

test("annule tout un groupe de révocations si une seule version est périmée", () => {
  const repository = new TransactionalMemoryRepository();
  const first = applicationSession(repository).record;
  repository.saveApplicationSession(first, createApplicationSessionAuditEvent({
    record: first, action: "application_session.created", correlationId: "batch-first-created",
  }));
  const second = createApplicationSession({
    identityId: identity.identityId, applicationId: application.applicationId,
    idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    now: new Date("2026-08-13T04:02:00Z"), authenticatedAt: new Date("2026-08-13T04:02:00Z"),
    randomUuidImpl: () => "00000000-0000-4000-8000-000000000045",
    randomBytesImpl: () => Buffer.alloc(32, 12),
  }).record;
  repository.saveApplicationSession(second, createApplicationSessionAuditEvent({
    record: second, action: "application_session.created", correlationId: "batch-second-created",
  }));
  const closures = [first, second].map((record, index) => {
    const revoked = revokeApplicationSession(record, {
      revokedByIdentityId: identity.identityId, reason: "Fermeture groupée demandée",
      now: new Date("2026-08-13T04:20:00Z"),
    });
    return {
      record: revoked,
      expectedVersion: index === 0 ? record.version : 99,
      auditEvent: createApplicationSessionAuditEvent({
        record: revoked, action: "application_session.revoked", actorId: identity.identityId,
        correlationId: `batch-${index}-revoked`,
      }),
    };
  });
  const beforeAuditCount = repository.auditCount();
  assert.throws(() => repository.revokeApplicationSessions(closures), /stale/);
  assert.equal(repository.getApplicationSession(first.sessionId).revokedAt, null);
  assert.equal(repository.getApplicationSession(second.sessionId).revokedAt, null);
  assert.equal(repository.auditCount(), beforeAuditCount);
});
