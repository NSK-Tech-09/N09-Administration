import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  createApplicationSessionAuthority, createCompositeApplicationSessionAuthority,
} from "./application-session-authority.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identityId = "00000000-0000-4000-8000-000000000001";
const applicationId = "n09-suivi-taches";
const baseTime = new Date("2026-08-13T08:00:00.000Z");

function audit(action, fields) {
  return createAuditEvent({
    action,
    result: "success",
    source: "application-session-authority-tests",
    correlationId: randomUUID(),
    ...fields,
  });
}

function seeded() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId,
    email: "fred@example.test",
    displayName: "Fred",
    status: "active",
  }, audit("identity.created", { subjectId: identityId }));
  repository.saveApplication({
    applicationId,
    displayName: "N09 – Suivi des tâches",
    status: "active",
    registrationPolicy: "closed",
  }, audit("application.registered", { applicationId }));
  return repository;
}

function authority(repository, mode, clock) {
  return createApplicationSessionAuthority({
    repository,
    config: {
      mode,
      applicationId,
      idleTtlMs: 60 * 60_000,
      absoluteTtlMs: 4 * 60 * 60_000,
      touchIntervalMs: 5 * 60_000,
    },
    now: () => new Date(clock.value),
  });
}

test("émet la preuve en mode préparatoire sans la rendre opposable", async () => {
  const repository = seeded();
  const clock = { value: baseTime };
  assert.equal(await authority(repository, "disabled", clock).issue({ identityId, applicationId }), null);

  const issuing = authority(repository, "issue", clock);
  const issued = await issuing.issue({ identityId, applicationId });
  assert.ok(issued.credential.sessionId);
  assert.equal(issued.credential.secret.length, 43);
  assert.equal((await issuing.assess({ identityId, applicationId, credential: null })).allowed, true);
  assert.equal(repository.listApplicationSessions(identityId).length, 1);
});

test("rend la session opposable, consolide son activité et permet sa révocation applicative", async () => {
  const repository = seeded();
  const clock = { value: baseTime };
  const enforcing = authority(repository, "enforce", clock);
  const issued = await enforcing.issue({ identityId, applicationId });

  assert.deepEqual(await enforcing.assess({ identityId, applicationId, credential: null }), {
    allowed: false, reasonCode: "session_required",
  });
  assert.equal((await enforcing.assess({
    identityId,
    applicationId,
    credential: { ...issued.credential, secret: "A".repeat(43) },
  })).reasonCode, "session_secret_invalid");
  assert.equal((await enforcing.assess({ identityId, applicationId, credential: issued.credential })).allowed, true);

  clock.value = new Date(baseTime.valueOf() + 6 * 60_000);
  assert.equal((await enforcing.assess({ identityId, applicationId, credential: issued.credential })).allowed, true);
  assert.equal(repository.getApplicationSession(issued.credential.sessionId).version, 2);

  const result = await enforcing.revokeForApplication({
    sessionId: issued.credential.sessionId,
    identityId,
    applicationId,
    reason: "Déconnexion demandée dans N09 – Suivi des tâches",
  });
  assert.equal(result.revoked, true);
  assert.equal((await enforcing.assess({ identityId, applicationId, credential: issued.credential })).reasonCode, "session_revoked");
  assert.equal(repository.auditSnapshot().at(-1).event.action, "application_session.revoked");
});

test("ferme et audite une expiration une seule fois sans divulguer la preuve", async () => {
  const repository = seeded();
  const clock = { value: baseTime };
  const enforcing = authority(repository, "enforce", clock);
  const issued = await enforcing.issue({ identityId, applicationId });
  clock.value = new Date(baseTime.valueOf() + 61 * 60_000);

  const result = await enforcing.assess({ identityId, applicationId, credential: issued.credential });
  assert.equal(result.reasonCode, "session_idle_expired");
  const record = repository.getApplicationSession(issued.credential.sessionId);
  assert.ok(record.revokedAt);
  const event = repository.auditSnapshot().at(-1).event;
  assert.equal(event.action, "application_session.expired");
  const serialized = JSON.stringify(event);
  assert.equal(serialized.includes(issued.credential.sessionId), false);
  assert.equal(serialized.includes(record.secretHash), false);
  assert.equal(repository.verifyAuditChain(), true);
});

test("route deux applications sans partager leurs preuves de session", async () => {
  const repository = seeded();
  const energyApplicationId = "n09-energie";
  repository.saveApplication({
    applicationId: energyApplicationId,
    displayName: "N09 – Énergie",
    status: "active",
    registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: energyApplicationId }));
  const clock = { value: baseTime };
  const tasks = authority(repository, "enforce", clock);
  const energy = createApplicationSessionAuthority({
    repository,
    config: {
      mode: "enforce", applicationId: energyApplicationId,
      idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000, touchIntervalMs: 5 * 60_000,
      contextLabel: "Connexion web N09 – Énergie",
      issueJustification: "Ouverture de la session applicative N09 – Énergie",
    },
    now: () => new Date(clock.value),
  });
  const composite = createCompositeApplicationSessionAuthority([tasks, energy]);
  const issued = await composite.issue({ identityId, applicationId: energyApplicationId });
  assert.ok(issued.credential.sessionId);
  assert.equal((await composite.assess({
    identityId, applicationId: energyApplicationId, credential: issued.credential,
  })).allowed, true);
  assert.equal((await composite.assess({
    identityId, applicationId, credential: issued.credential,
  })).reasonCode, "session_context_mismatch");
  assert.equal(composite.issuesFor(energyApplicationId), true);
  assert.equal(composite.enforcesFor("application-inconnue"), false);
});
