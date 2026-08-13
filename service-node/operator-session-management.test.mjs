import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createApplicationSession, createApplicationSessionAuditEvent } from "./application-session.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  authorizeSessionRevocationAdministration,
  createOperatorSessionManagement,
  OperatorSessionError,
  SESSION_REVOCATION_PERMISSION,
} from "./operator-session-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operatorId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const targetId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const now = new Date("2026-08-13T12:00:00.000Z");
let auditSequence = 0;

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "operator-session-tests",
    correlationId: `${action}-${++auditSequence}`, occurredAt: now,
    justification: "Préparation contrôlée du test", ...changes,
  });
}

function seededRepository({ permission = SESSION_REVOCATION_PERMISSION, scopeType = null } = {}) {
  const repository = new TransactionalMemoryRepository();
  for (const [identityId, displayName] of [[operatorId, "Opérateur"], [targetId, "Personne cible"]]) {
    repository.saveIdentity({
      identityId, email: `${identityId[0]}@example.test`, displayName, status: "active",
    }, audit("identity.created", { subjectId: identityId }));
  }
  for (const [applicationId, displayName] of [
    [ADMIN_APPLICATION_ID, "N09 – Administration"],
    ["n09-suivi-taches", "N09 – Suivi des tâches"],
  ]) {
    repository.saveApplication({ applicationId, displayName, status: "active", registrationPolicy: "closed" },
      audit("application.registered", { applicationId }));
  }
  repository.saveAssignment({
    assignmentId: "10000000-0000-4000-8000-000000000053",
    subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    roleId: "session-revocation-administrator", permissions: [permission],
    scopeType, scopeId: scopeType ? "hors-perimetre-global" : null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason: "Pouvoir séparé pour le test", decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

function addSession(repository, {
  identityId,
  applicationId = "n09-suivi-taches",
  sessionId,
  byte,
  issuedAt = now,
}) {
  const created = createApplicationSession({
    identityId, applicationId, idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: issuedAt, now: issuedAt, contextLabel: "Navigateur de test",
    randomUuidImpl: () => sessionId, randomBytesImpl: () => Buffer.alloc(32, byte),
  });
  repository.saveApplicationSession(created.record, createApplicationSessionAuditEvent({
    record: created.record, action: "application_session.created", occurredAt: issuedAt,
  }));
  return created.record;
}

test("autorise seulement le pouvoir séparé dans le périmètre global", async () => {
  assert.equal((await authorizeSessionRevocationAdministration(seededRepository(), operatorId, now)).allowed, true);
  assert.equal((await authorizeSessionRevocationAdministration(
    seededRepository({ permission: "administration:access:read" }), operatorId, now,
  )).allowed, false);
  const wrongScope = await authorizeSessionRevocationAdministration(
    seededRepository({ scopeType: "site" }), operatorId, now,
  );
  assert.equal(wrongScope.allowed, false);
  assert.equal(wrongScope.reasonCode, "scope_mismatch");
});

test("présente toutes les sessions actives sans secret et marque la courante", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    identityId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  addSession(repository, {
    identityId: targetId, sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  addSession(repository, {
    identityId: targetId, sessionId: "00000000-0000-4000-8000-000000000054", byte: 4,
    issuedAt: new Date("2026-08-13T06:00:00.000Z"),
  });
  const sessions = await createOperatorSessionManagement({ repository, now: () => now }).listActive({
    operatorIdentityId: operatorId, currentSessionId: current.sessionId,
  });
  assert.equal(sessions.length, 2);
  assert.equal(sessions.filter((session) => session.current).length, 1);
  assert.deepEqual(new Set(sessions.map((session) => session.identityName)), new Set(["Opérateur", "Personne cible"]));
  assert.equal(JSON.stringify(sessions).includes("secretHash"), false);
});

test("révoque une session étrangère avec acteur, motif et audit exacts", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    identityId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  const target = addSession(repository, {
    identityId: targetId, sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  const management = createOperatorSessionManagement({ repository, now: () => now });
  const result = await management.revokeOne({
    operatorIdentityId: operatorId, currentSessionId: current.sessionId,
    targetIdentityId: targetId, targetSessionId: target.sessionId, expectedVersion: target.version,
    justification: "Session devenue inutile après contrôle humain",
    correlationId: "lot53-correlation",
  });
  assert.deepEqual(result, { correlationId: "lot53-correlation", revoked: 1 });
  const stored = repository.getApplicationSession(target.sessionId);
  assert.equal(stored.revokedByIdentityId, operatorId);
  assert.equal(stored.revocationReason, "Session devenue inutile après contrôle humain");
  const event = repository.auditSnapshot().at(-1).event;
  assert.equal(event.action, "application_session.revoked");
  assert.equal(event.actor_id, operatorId);
  assert.equal(event.subject_id, targetId);
  assert.equal(JSON.stringify(event).includes(target.sessionId), false);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse session courante, version périmée, cible hors identité et pouvoir absent", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    identityId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  const target = addSession(repository, {
    identityId: targetId, sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  const management = createOperatorSessionManagement({ repository, now: () => now });
  const base = {
    operatorIdentityId: operatorId, currentSessionId: current.sessionId,
    targetIdentityId: targetId, targetSessionId: target.sessionId, expectedVersion: 1,
    justification: "Motif suffisamment explicite pour le contrôle",
  };
  await assert.rejects(management.revokeOne({
    ...base, targetIdentityId: operatorId, targetSessionId: current.sessionId,
  }), (error) => error instanceof OperatorSessionError && error.code === "current_session_requires_logout");
  await assert.rejects(management.revokeOne({ ...base, expectedVersion: 99 }),
    (error) => error instanceof OperatorSessionError && error.code === "session_version_conflict");
  await assert.rejects(management.revokeOne({ ...base, targetIdentityId: operatorId }),
    (error) => error instanceof OperatorSessionError && error.code === "session_not_in_target_scope");
  const denied = createOperatorSessionManagement({
    repository: seededRepository({ permission: "administration:access:read" }), now: () => now,
  });
  await assert.rejects(denied.listActive({ operatorIdentityId: operatorId, currentSessionId: current.sessionId }),
    (error) => error instanceof OperatorSessionError && error.code === "session_revocation_not_allowed");
  assert.equal(repository.getApplicationSession(target.sessionId).revokedAt, null);
});
