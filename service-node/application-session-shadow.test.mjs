import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createApplicationSessionShadow } from "./application-session-shadow.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const applicationId = "n09-administration";
const config = {
  mode: "observe", applicationId,
  idleTtlMs: 30 * 60_000, absoluteTtlMs: 8 * 60 * 60_000, touchIntervalMs: 5 * 60_000,
};

const audit = (action, values = {}) => createAuditEvent({
  action, result: "success", source: "session-shadow-tests", correlationId: randomUUID(), ...values,
});

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId, email: "personne@example.test", displayName: "Personne NSK", status: "active",
  }, audit("identity.created", { subjectId: identityId }));
  repository.saveApplication({
    applicationId, displayName: "N09 – Administration", status: "active", registrationPolicy: "closed",
  }, audit("application.registered", { applicationId }));
  return repository;
}

test("reste totalement inerte lorsque l'observation n'est pas explicitement activée", async () => {
  const repository = {
    saveApplicationSession: () => { throw new Error("must not run"); },
    getApplicationSession: () => { throw new Error("must not run"); },
  };
  const shadow = createApplicationSessionShadow({ repository, config: { ...config, mode: "disabled" } });
  assert.equal(await shadow.enroll({ identityId }), null);
  assert.deepEqual(await shadow.observe({ identityId, credential: null }), { outcome: "disabled" });
  assert.deepEqual(shadow.snapshot(), {
    mode: "disabled",
    enrollments: { succeeded: 0, failed: 0 },
    observations: { active: 0, notEnrolled: 0, divergent: 0, unavailable: 0 },
    touches: { succeeded: 0, failed: 0 },
    revocations: { succeeded: 0, failed: 0 },
  });
});

test("enregistre, compare et consolide une activité à fréquence bornée", async () => {
  const repository = seededRepository();
  let clock = new Date("2026-08-13T08:00:00.000Z");
  const logs = [];
  const shadow = createApplicationSessionShadow({
    repository, config, now: () => new Date(clock), logger: { info: (line) => logs.push(line) },
  });
  const credential = await shadow.enroll({ identityId, authenticatedAt: clock });
  assert.match(credential.sessionId, /^[0-9a-f-]{36}$/);
  assert.match(credential.secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await shadow.observe({ credential, identityId })).outcome, "active");
  assert.equal(repository.getApplicationSession(credential.sessionId).version, 1);

  clock = new Date(clock.valueOf() + 6 * 60_000);
  assert.equal((await shadow.observe({ credential, identityId })).outcome, "active");
  assert.equal(repository.getApplicationSession(credential.sessionId).version, 2);
  assert.deepEqual(shadow.snapshot(), {
    mode: "observe",
    enrollments: { succeeded: 1, failed: 0 },
    observations: { active: 2, notEnrolled: 0, divergent: 0, unavailable: 0 },
    touches: { succeeded: 1, failed: 0 },
    revocations: { succeeded: 0, failed: 0 },
  });
  const serializedLogs = logs.join("\n");
  assert.doesNotMatch(serializedLogs, new RegExp(credential.sessionId, "i"));
  assert.doesNotMatch(serializedLogs, new RegExp(credential.secret));
  assert.doesNotMatch(serializedLogs, /personne@example\.test|60a40cd7/i);
});

test("mesure une divergence sans la transformer en décision d'accès", async () => {
  const repository = seededRepository();
  const shadow = createApplicationSessionShadow({ repository, config, logger: { info: () => {} } });
  const credential = await shadow.enroll({ identityId });
  const result = await shadow.observe({ credential: { ...credential, secret: "A".repeat(43) }, identityId });
  assert.deepEqual(result, { outcome: "divergent", reasonCode: "session_secret_invalid" });
  assert.equal(shadow.snapshot().observations.divergent, 1);
});

test("absorbe les indisponibilités et ne journalise aucune donnée fournie", async () => {
  const sensitiveIdentity = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
  const sensitiveSession = "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702";
  const sensitiveSecret = "B".repeat(43);
  const logs = [];
  const repository = {
    saveApplicationSession: async () => { throw new Error(`database failed for ${sensitiveIdentity}`); },
    getApplicationSession: async () => { throw new Error(`missing ${sensitiveSession} ${sensitiveSecret}`); },
  };
  const shadow = createApplicationSessionShadow({ repository, config, logger: { info: (line) => logs.push(line) } });
  assert.equal(await shadow.enroll({ identityId: sensitiveIdentity }), null);
  assert.deepEqual(await shadow.observe({
    identityId: sensitiveIdentity, credential: { sessionId: sensitiveSession, secret: sensitiveSecret },
  }), { outcome: "unavailable" });
  const serializedLogs = logs.join("\n");
  assert.doesNotMatch(serializedLogs, /60a40cd7|b14ad8d3|BBBB/);
  assert.deepEqual(shadow.snapshot(), {
    mode: "observe",
    enrollments: { succeeded: 0, failed: 1 },
    observations: { active: 0, notEnrolled: 0, divergent: 0, unavailable: 1 },
    touches: { succeeded: 0, failed: 0 },
    revocations: { succeeded: 0, failed: 0 },
  });
});
