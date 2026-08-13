import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createApplicationSession, createApplicationSessionAuditEvent } from "./application-session.mjs";
import { createPersonalSessionManagement, PersonalSessionError } from "./personal-session-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const otherIdentityId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const now = new Date("2026-08-13T12:00:00.000Z");
let auditSequence = 0;

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "personal-session-tests",
    correlationId: `${action}-${++auditSequence}`, occurredAt: now, ...changes,
  });
}

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  for (const [candidate, displayName] of [[identityId, "Personne NSK"], [otherIdentityId, "Autre personne"]]) {
    repository.saveIdentity({
      identityId: candidate, email: `${candidate[0]}@example.test`, displayName, status: "active",
    }, audit("identity.created", { subjectId: candidate }));
  }
  for (const [applicationId, displayName] of [
    ["n09-administration", "N09 – Administration"],
    ["n09-suivi-taches", "N09 – Suivi des tâches"],
  ]) {
    repository.saveApplication({ applicationId, displayName, status: "active", registrationPolicy: "closed" },
      audit("application.registered", { applicationId }));
  }
  return repository;
}

function addSession(repository, {
  identity = identityId,
  applicationId = "n09-administration",
  sessionId,
  byte,
  issuedAt = now,
}) {
  const created = createApplicationSession({
    identityId: identity,
    applicationId,
    idleTtlMs: 60 * 60_000,
    absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: issuedAt,
    now: issuedAt,
    contextLabel: applicationId === "n09-administration" ? "Navigateur Administration" : "Navigateur Tâches",
    randomUuidImpl: () => sessionId,
    randomBytesImpl: () => Buffer.alloc(32, byte),
  });
  repository.saveApplicationSession(created.record, createApplicationSessionAuditEvent({
    record: created.record, action: "application_session.created", occurredAt: issuedAt,
  }));
  return created;
}

test("présente seulement les sessions de la personne et identifie la session courante", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  addSession(repository, {
    applicationId: "n09-suivi-taches", sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  addSession(repository, {
    identity: otherIdentityId, sessionId: "00000000-0000-4000-8000-000000000053", byte: 3,
  });
  const management = createPersonalSessionManagement({ repository, now: () => now });
  const sessions = await management.listOwn({ identityId, currentSessionId: current.record.sessionId });
  assert.equal(sessions.length, 2);
  assert.equal(sessions.filter((session) => session.current).length, 1);
  assert.deepEqual(sessions.map((session) => session.applicationName).sort(), [
    "N09 – Administration", "N09 – Suivi des tâches",
  ]);
  assert.equal(JSON.stringify(sessions).includes("secretHash"), false);
});

test("révoque une session distante appartenant à la personne avec audit", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  const target = addSession(repository, {
    applicationId: "n09-suivi-taches", sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  const management = createPersonalSessionManagement({ repository, now: () => now });
  assert.deepEqual(await management.revokeOne({
    identityId,
    currentSessionId: current.record.sessionId,
    targetSessionId: target.record.sessionId,
    expectedVersion: target.record.version,
  }), { revoked: 1 });
  assert.equal(repository.getApplicationSession(target.record.sessionId).revokedByIdentityId, identityId);
  assert.equal(repository.getApplicationSession(current.record.sessionId).revokedAt, null);
  assert.equal(repository.auditSnapshot().at(-1).event.action, "application_session.revoked");
});

test("refuse la session courante, une session étrangère et une version périmée", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  const target = addSession(repository, {
    applicationId: "n09-suivi-taches", sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  const foreign = addSession(repository, {
    identity: otherIdentityId, sessionId: "00000000-0000-4000-8000-000000000053", byte: 3,
  });
  const management = createPersonalSessionManagement({ repository, now: () => now });
  await assert.rejects(management.revokeOne({
    identityId, currentSessionId: current.record.sessionId,
    targetSessionId: current.record.sessionId, expectedVersion: 1,
  }), (error) => error instanceof PersonalSessionError && error.code === "current_session_requires_logout");
  await assert.rejects(management.revokeOne({
    identityId, currentSessionId: current.record.sessionId,
    targetSessionId: foreign.record.sessionId, expectedVersion: 1,
  }), (error) => error instanceof PersonalSessionError && error.code === "session_not_owned");
  await assert.rejects(management.revokeOne({
    identityId, currentSessionId: current.record.sessionId,
    targetSessionId: target.record.sessionId, expectedVersion: 99,
  }), (error) => error instanceof PersonalSessionError && error.code === "session_version_conflict");
  assert.equal(repository.getApplicationSession(target.record.sessionId).revokedAt, null);
  assert.equal(repository.getApplicationSession(foreign.record.sessionId).revokedAt, null);
});

test("ferme atomiquement toutes les autres sessions actives et conserve la courante", async () => {
  const repository = seededRepository();
  const current = addSession(repository, {
    sessionId: "00000000-0000-4000-8000-000000000051", byte: 1,
  });
  const first = addSession(repository, {
    applicationId: "n09-suivi-taches", sessionId: "00000000-0000-4000-8000-000000000052", byte: 2,
  });
  const second = addSession(repository, {
    issuedAt: new Date("2026-08-13T11:30:00.000Z"),
    sessionId: "00000000-0000-4000-8000-000000000054", byte: 4,
  });
  const expired = addSession(repository, {
    issuedAt: new Date("2026-08-13T06:00:00.000Z"),
    sessionId: "00000000-0000-4000-8000-000000000055", byte: 5,
  });
  const management = createPersonalSessionManagement({ repository, now: () => now });
  assert.deepEqual(await management.revokeAllOthers({
    identityId, currentSessionId: current.record.sessionId,
  }), { revoked: 2 });
  assert.equal(repository.getApplicationSession(current.record.sessionId).revokedAt, null);
  assert.ok(repository.getApplicationSession(first.record.sessionId).revokedAt);
  assert.ok(repository.getApplicationSession(second.record.sessionId).revokedAt);
  assert.equal(repository.getApplicationSession(expired.record.sessionId).revokedAt, null);
  assert.equal(repository.verifyAuditChain(), true);
});
