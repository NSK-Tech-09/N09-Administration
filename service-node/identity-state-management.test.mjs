import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  createApplicationSession,
  createApplicationSessionAuditEvent,
  touchApplicationSession,
} from "./application-session.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  authorizeIdentityLifecycleAdministration,
  authorizeIdentityReactivationAdministration,
  authorizeIdentitySuspensionAdministration,
  createIdentityStateManagement,
  IDENTITY_REACTIVATION_PERMISSION,
  IDENTITY_SUSPENSION_PERMISSION,
  IdentityStateError,
} from "./identity-state-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operatorId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const targetId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const now = new Date("2026-08-13T12:00:00.000Z");
let sequence = 0;

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "identity-state-tests",
    correlationId: `${action}-${++sequence}`, occurredAt: now,
    justification: "Préparation contrôlée du test", ...changes,
  });
}

function seededRepository({ permissions = [IDENTITY_SUSPENSION_PERMISSION], scopeType = null } = {}) {
  const repository = new TransactionalMemoryRepository();
  for (const [identityId, displayName] of [[operatorId, "Opérateur"], [targetId, "Personne cible"]]) {
    repository.saveIdentity({
      identityId, email: `${identityId[0]}@example.test`, displayName, status: "active",
    }, audit("identity.created", { subjectId: identityId }));
  }
  for (const [applicationId, displayName] of [
    [ADMIN_APPLICATION_ID, "N09 – Administration"], ["n09-suivi-taches", "N09 – Suivi des tâches"],
  ]) {
    repository.saveApplication({ applicationId, displayName, status: "active", registrationPolicy: "closed" },
      audit("application.registered", { applicationId }));
  }
  repository.saveAssignment({
    assignmentId: "10000000-0000-4000-8000-000000000054",
    subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    roleId: "identity-lifecycle-test-administrator", permissions,
    scopeType, scopeId: scopeType ? "hors-perimetre-global" : null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason: "Pouvoir séparé pour le test", decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

function addSession(repository, { sessionId, applicationId = "n09-suivi-taches", issuedAt = new Date("2026-08-13T11:30:00.000Z") }) {
  const created = createApplicationSession({
    identityId: targetId, applicationId, idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: issuedAt, now: issuedAt, contextLabel: "Navigateur de test",
    randomUuidImpl: () => sessionId, randomBytesImpl: () => Buffer.alloc(32, Number(sessionId.slice(-2))),
  });
  repository.saveApplicationSession(created.record, createApplicationSessionAuditEvent({
    record: created.record, action: "application_session.created", occurredAt: issuedAt,
  }));
  return created.record;
}

test("autorise uniquement le pouvoir de suspension dans le périmètre global", async () => {
  assert.equal((await authorizeIdentitySuspensionAdministration(seededRepository(), operatorId, now)).allowed, true);
  assert.equal((await authorizeIdentitySuspensionAdministration(
    seededRepository({ permissions: ["administration:sessions:revoke"] }), operatorId, now,
  )).allowed, false);
  assert.equal((await authorizeIdentitySuspensionAdministration(
    seededRepository({ scopeType: "site" }), operatorId, now,
  )).reasonCode, "scope_mismatch");
});

test("sépare strictement les pouvoirs de suspension et de réactivation", async () => {
  const suspensionOnly = seededRepository();
  assert.equal((await authorizeIdentitySuspensionAdministration(suspensionOnly, operatorId, now)).allowed, true);
  assert.equal((await authorizeIdentityReactivationAdministration(suspensionOnly, operatorId, now)).allowed, false);
  const reactivationOnly = seededRepository({ permissions: [IDENTITY_REACTIVATION_PERMISSION] });
  assert.equal((await authorizeIdentitySuspensionAdministration(reactivationOnly, operatorId, now)).allowed, false);
  assert.equal((await authorizeIdentityReactivationAdministration(reactivationOnly, operatorId, now)).allowed, true);
  assert.deepEqual(await authorizeIdentityLifecycleAdministration(reactivationOnly, operatorId, now), {
    allowed: true, canSuspend: false, canReactivate: true, reasonCode: "allowed",
  });
});

test("suspend l’identité et révoque toutes ses sessions actives dans une seule chaîne d’audit", async () => {
  const repository = seededRepository();
  const first = addSession(repository, { sessionId: "00000000-0000-4000-8000-000000000061" });
  const second = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000062", applicationId: ADMIN_APPLICATION_ID,
  });
  const result = await createIdentityStateManagement({ repository, now: () => now }).suspend({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Départ confirmé de la personne hors de l’écosystème NSK",
    correlationId: "lot54-correlation",
  });
  assert.equal(result.revokedSessions, 2);
  assert.equal(repository.getIdentity(targetId).status, "suspended");
  for (const sessionId of [first.sessionId, second.sessionId]) {
    const stored = repository.getApplicationSession(sessionId);
    assert.equal(stored.revokedByIdentityId, operatorId);
    assert.equal(stored.revocationReason, "Départ confirmé de la personne hors de l’écosystème NSK");
  }
  const events = repository.auditSnapshot().slice(-3).map((entry) => entry.event);
  assert.deepEqual(events.map((event) => event.action), [
    "identity.suspended", "application_session.revoked", "application_session.revoked",
  ]);
  assert.ok(events.every((event) => event.correlation_id === "lot54-correlation"));
  assert.equal(JSON.stringify(events).includes(first.sessionId), false);
  assert.equal(repository.verifyAuditChain(), true);
});

test("ne révoque pas une session déjà expirée et ne permet pas l’auto-suspension", async () => {
  const repository = seededRepository();
  const expired = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000063",
    issuedAt: new Date("2026-08-13T06:00:00.000Z"),
  });
  const management = createIdentityStateManagement({ repository, now: () => now });
  await assert.rejects(management.suspend({
    operatorIdentityId: operatorId, targetIdentityId: operatorId, expectedStatus: "active",
    justification: "Suspension volontaire nécessitant une gouvernance distincte",
  }), (error) => error instanceof IdentityStateError && error.code === "self_suspension_requires_separate_governance");
  const result = await management.suspend({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Suspension justifiée après contrôle humain complet",
  });
  assert.equal(result.revokedSessions, 0);
  assert.equal(repository.getApplicationSession(expired.sessionId).revokedAt, null);
});

test("annule également la suspension si une session change concurremment", async () => {
  const repository = seededRepository();
  const original = addSession(repository, { sessionId: "00000000-0000-4000-8000-000000000064" });
  const concurrentRepository = {
    getIdentity: (...args) => repository.getIdentity(...args),
    getApplication: (...args) => repository.getApplication(...args),
    listAssignments: (...args) => repository.listAssignments(...args),
    listIdentities: (...args) => repository.listIdentities(...args),
    listApplicationSessions: (...args) => repository.listApplicationSessions(...args),
    reactivateIdentity: (...args) => repository.reactivateIdentity(...args),
    suspendIdentityAndRevokeSessions: (bundle) => {
      const touched = touchApplicationSession(original, { now: new Date("2026-08-13T11:45:00.000Z") });
      repository.touchApplicationSession(touched, original.version);
      return repository.suspendIdentityAndRevokeSessions(bundle);
    },
  };
  await assert.rejects(createIdentityStateManagement({
    repository: concurrentRepository, now: () => now,
  }).suspend({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Suspension interrompue par une modification concurrente",
  }), /stale application session version/);
  assert.equal(repository.getIdentity(targetId).status, "active");
  assert.equal(repository.getApplicationSession(original.sessionId).revokedAt, null);
  assert.equal(repository.verifyAuditChain(), true);
});

test("annule la suspension si une nouvelle session apparaît pendant la décision", async () => {
  const repository = seededRepository();
  addSession(repository, { sessionId: "00000000-0000-4000-8000-000000000065" });
  const concurrentRepository = {
    getIdentity: (...args) => repository.getIdentity(...args),
    getApplication: (...args) => repository.getApplication(...args),
    listAssignments: (...args) => repository.listAssignments(...args),
    listIdentities: (...args) => repository.listIdentities(...args),
    listApplicationSessions: (...args) => repository.listApplicationSessions(...args),
    reactivateIdentity: (...args) => repository.reactivateIdentity(...args),
    suspendIdentityAndRevokeSessions: (bundle) => {
      addSession(repository, {
        sessionId: "00000000-0000-4000-8000-000000000066",
        applicationId: ADMIN_APPLICATION_ID,
      });
      return repository.suspendIdentityAndRevokeSessions(bundle);
    },
  };
  await assert.rejects(createIdentityStateManagement({
    repository: concurrentRepository, now: () => now,
  }).suspend({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Suspension interrompue par une nouvelle session concurrente",
  }), /active session set changed/);
  assert.equal(repository.getIdentity(targetId).status, "active");
  assert.equal(repository.verifyAuditChain(), true);
});

test("réactive une identité suspendue sans restaurer ses anciennes sessions", async () => {
  const repository = seededRepository({
    permissions: [IDENTITY_SUSPENSION_PERMISSION, IDENTITY_REACTIVATION_PERMISSION],
  });
  const activeSession = addSession(repository, { sessionId: "00000000-0000-4000-8000-000000000067" });
  const expiredSession = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000069",
    issuedAt: new Date("2026-08-13T06:00:00.000Z"),
  });
  const management = createIdentityStateManagement({ repository, now: () => now });
  await management.suspend({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Suspension préalable pour vérifier une réactivation sans résurrection",
  });
  const revokedBefore = repository.getApplicationSession(activeSession.sessionId);
  assert.ok(revokedBefore.revokedAt);
  const result = await management.reactivate({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "suspended",
    justification: "Retour autorisé après une nouvelle décision humaine explicitement contrôlée",
    correlationId: "lot55-correlation",
  });
  assert.equal(result.restoredSessions, 0);
  assert.equal(repository.getIdentity(targetId).status, "active");
  assert.deepEqual(repository.getApplicationSession(activeSession.sessionId), revokedBefore);
  assert.equal(repository.getApplicationSession(expiredSession.sessionId).revokedAt, null);
  assert.ok(new Date(repository.getApplicationSession(expiredSession.sessionId).absoluteExpiresAt) < now);
  const event = repository.auditSnapshot().at(-1).event;
  assert.equal(event.action, "identity.reactivated");
  assert.equal(event.correlation_id, "lot55-correlation");
  assert.deepEqual(event.new_value, { status: "active", active_sessions: 0, restored_sessions: 0 });
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse la réactivation si une session active existe encore", async () => {
  const repository = seededRepository({ permissions: [IDENTITY_REACTIVATION_PERMISSION] });
  repository.saveIdentity({ ...repository.getIdentity(targetId), status: "suspended" }, audit("identity.suspended", {
    actorId: operatorId, subjectId: targetId,
    previousValue: { status: "active" }, newValue: { status: "suspended" },
  }));
  addSession(repository, { sessionId: "00000000-0000-4000-8000-000000000068" });
  await assert.rejects(createIdentityStateManagement({ repository, now: () => now }).reactivate({
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "suspended",
    justification: "Réactivation volontairement refusée à cause d’une session encore active",
  }), /suspended identity still has active sessions/);
  assert.equal(repository.getIdentity(targetId).status, "suspended");
  assert.equal(repository.verifyAuditChain(), true);
});
