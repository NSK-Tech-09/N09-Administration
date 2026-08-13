import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAdministrationSessionAuthority } from "./administration-session-authority.mjs";
import { createAuditEvent } from "./audit.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const applicationId = "n09-administration";
const config = {
  mode: "enforce",
  applicationId,
  idleTtlMs: 30 * 60_000,
  absoluteTtlMs: 8 * 60 * 60_000,
  touchIntervalMs: 5 * 60_000,
};

const audit = (action, values = {}) => createAuditEvent({
  action,
  result: "success",
  source: "administration-session-authority-tests",
  correlationId: randomUUID(),
  ...values,
});

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId,
    email: "personne@example.test",
    displayName: "Personne NSK",
    status: "active",
  }, audit("identity.created", { subjectId: identityId }));
  repository.saveApplication({
    applicationId,
    displayName: "N09 – Administration",
    status: "active",
    registrationPolicy: "closed",
  }, audit("application.registered", { applicationId }));
  return repository;
}

test("émet, contrôle puis révoque la session Administration de façon opposable", async () => {
  const repository = seededRepository();
  let clock = new Date("2026-08-13T09:00:00.000Z");
  const authority = createAdministrationSessionAuthority({
    repository,
    config,
    now: () => new Date(clock),
    logger: { info: () => {} },
  });
  const credential = await authority.issue({ identityId, authenticatedAt: clock });
  assert.equal((await authority.assess({ credential, identityId })).allowed, true);
  assert.deepEqual(await authority.assess({
    credential: { ...credential, secret: "A".repeat(43) },
    identityId,
  }), {
    allowed: false,
    outcome: "divergent",
    reasonCode: "session_secret_invalid",
  });

  clock = new Date(clock.valueOf() + 6 * 60_000);
  assert.equal((await authority.assess({ credential, identityId })).allowed, true);
  assert.equal(repository.getApplicationSession(credential.sessionId).version, 2);

  assert.deepEqual(await authority.revokeCurrent({ credential, identityId }), {
    revoked: true,
    reasonCode: "session_revoked",
  });
  assert.equal((await authority.assess({ credential, identityId })).reasonCode, "session_revoked");
  const event = repository.auditSnapshot().at(-1).event;
  assert.equal(event.action, "application_session.revoked");
  assert.equal(event.actor_id, identityId);
  const serialized = JSON.stringify(repository.auditSnapshot());
  assert.equal(serialized.includes(credential.secret), false);
  assert.equal(serialized.includes(credential.sessionId), false);
});

test("ferme l'accès si la preuve manque ou si le registre est indisponible", async () => {
  const authority = createAdministrationSessionAuthority({
    repository: {
      getApplicationSession: async () => { throw new Error("database unavailable"); },
      saveApplicationSession: async () => { throw new Error("database unavailable"); },
    },
    config,
    logger: { info: () => {} },
  });
  assert.equal((await authority.assess({ credential: null, identityId })).reasonCode, "session_required");
  assert.deepEqual(await authority.assess({
    credential: { sessionId: randomUUID(), secret: "S".repeat(43) },
    identityId,
  }), {
    allowed: false,
    outcome: "unavailable",
    reasonCode: "session_registry_unavailable",
  });
  await assert.rejects(() => authority.issue({ identityId }), /registry_unavailable/);
});

test("conserve l'observation inopposable avant la bascule", async () => {
  const authority = createAdministrationSessionAuthority({
    repository: {
      getApplicationSession: async () => { throw new Error("database unavailable"); },
      saveApplicationSession: async () => { throw new Error("database unavailable"); },
    },
    config: { ...config, mode: "observe" },
    logger: { info: () => {} },
  });
  assert.equal(await authority.issue({ identityId }), null);
  assert.deepEqual(await authority.observe({
    credential: { sessionId: randomUUID(), secret: "S".repeat(43) },
    identityId,
  }), { outcome: "unavailable" });
  assert.equal((await authority.assess({ credential: null, identityId })).allowed, true);
});
