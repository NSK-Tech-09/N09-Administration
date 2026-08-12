import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  prepareNotificationBatch, receiveNotificationEvents,
} from "./notification-ingress.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const applicationId = "n09-suivi-taches";
const principal = { applicationId, audience: applicationId, correlationId: randomUUID() };
const now = new Date("2026-08-12T12:00:00.000Z");
const event = {
  event_id: "event_0123456789abcdefabcd",
  event_type: "task.created",
  task_id: "task_1",
  site_id: "site_1",
  actor_id: "user_1",
  aggregate_id: "task_1",
  payload: { changed_fields: ["priority", "subject"], task_version: 1 },
  occurred_at: "2026-08-12T11:59:00.000Z",
};

function repository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveApplication({
    applicationId, displayName: "N09 – Suivi des tâches",
    status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "notification-tests",
    correlationId: randomUUID(), applicationId,
  }));
  return repository;
}

test("normalise le contrat sans coordonnee ni secret", () => {
  const prepared = prepareNotificationBatch({ contract_version: 1, events: [event] }, { now });
  assert.equal(prepared.contractVersion, 1);
  assert.equal(prepared.events[0].eventType, "task.created");
  assert.match(prepared.events[0].eventHash, /^[0-9a-f]{64}$/);
  assert.deepEqual(prepared.events[0].payload, {
    changed_fields: ["priority", "subject"], task_version: 1,
  });
  assert.doesNotMatch(JSON.stringify(prepared), /email|secret|token|password/i);
});

test("refuse les champs inconnus, types fictifs, doublons et donnees sensibles", () => {
  assert.throws(() => prepareNotificationBatch({
    contract_version: 1, events: [{ ...event, event_type: "email.send" }],
  }, { now }), /invalid_notification_event_type/);
  assert.throws(() => prepareNotificationBatch({
    contract_version: 1, events: [{ ...event, payload: { recipient_email: "x@example.invalid" } }],
  }, { now }), /invalid_notification_event_payload/);
  assert.throws(() => prepareNotificationBatch({
    contract_version: 1, events: [{ ...event, unknown: true }],
  }, { now }), /invalid_notification_event/);
  assert.throws(() => prepareNotificationBatch({
    contract_version: 1, events: [event, event],
  }, { now }), /duplicate_notification_event_in_batch/);
});

test("recoit une fois puis repond de facon idempotente", async () => {
  const target = repository();
  const before = target.auditCount();
  const first = await receiveNotificationEvents({
    repository: target, principal, payload: { contract_version: 1, events: [event] }, now,
  });
  assert.equal(first.status, 202);
  assert.deepEqual(first.body, { contract_version: 1, accepted: 1, already_present: 0 });
  assert.equal(target.auditCount(), before + 1);
  assert.equal(target.getNotificationEvent(applicationId, event.event_id).status, "pending");

  const replay = await receiveNotificationEvents({
    repository: target, principal, payload: { contract_version: 1, events: [event] }, now,
  });
  assert.equal(replay.status, 200);
  assert.deepEqual(replay.body, { contract_version: 1, accepted: 0, already_present: 1 });
  assert.equal(target.auditCount(), before + 1);
  assert.equal(target.verifyAuditChain(), true);
});

test("refuse un conflit d'identite d'evenement sans mutation partielle", async () => {
  const target = repository();
  await receiveNotificationEvents({
    repository: target, principal, payload: { contract_version: 1, events: [event] }, now,
  });
  const conflict = await receiveNotificationEvents({
    repository: target, principal,
    payload: { contract_version: 1, events: [{ ...event, payload: { task_version: 2 } }] }, now,
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error, "notification_event_identity_conflict");
  assert.deepEqual(target.getNotificationEvent(applicationId, event.event_id).payload,
    { changed_fields: ["priority", "subject"], task_version: 1 });
});

test("ferme l'entree sans preuve et isole l'audience applicative", async () => {
  const target = repository();
  const payload = { contract_version: 1, events: [event] };
  assert.equal((await receiveNotificationEvents({ repository: target, principal: null, payload, now })).status, 401);
  assert.equal((await receiveNotificationEvents({
    repository: target, principal: { applicationId, audience: "autre-application" }, payload, now,
  })).status, 403);
  assert.equal(target.listNotificationEvents().length, 0);
});
