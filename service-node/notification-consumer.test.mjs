import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { consumeNotificationEvents, notificationRetryDelayMs } from "./notification-consumer.mjs";
import { receiveNotificationEvents } from "./notification-ingress.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const applicationId = "n09-suivi-taches";
const eventId = "event_abcdef0123456789abcd";
const event = {
  event_id: eventId, event_type: "task.updated", task_id: "task_1", site_id: "site_1",
  actor_id: null, aggregate_id: "task_1", payload: { task_version: 2 },
  occurred_at: "2026-08-12T10:00:00.000Z",
};

async function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveApplication({
    applicationId, displayName: "N09 – Suivi des tâches", status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "consumer-tests",
    correlationId: randomUUID(), applicationId,
  }));
  const received = await receiveNotificationEvents({
    repository, principal: { applicationId, audience: applicationId },
    payload: { contract_version: 1, events: [event] },
    now: new Date("2026-08-12T10:01:00.000Z"),
  });
  assert.equal(received.status, 202);
  return repository;
}

test("traite une remise une seule fois et clot sa prise en charge", async () => {
  const repository = await seededRepository();
  const seen = [];
  const clock = () => new Date("2026-08-12T10:02:00.000Z");
  const result = await consumeNotificationEvents({
    repository, workerId: "notification-worker-1", now: clock,
    handle: async (item) => seen.push(item.eventId),
  });
  assert.deepEqual(result, { claimed: 1, processed: 1, retried: 0, quarantined: 0 });
  assert.deepEqual(seen, [eventId]);
  const stored = repository.getNotificationEvent(applicationId, eventId);
  assert.equal(stored.status, "processed");
  assert.equal(stored.processingAttempts, 1);
  assert.equal(stored.claimedBy, null);
  assert.equal((await consumeNotificationEvents({
    repository, workerId: "notification-worker-1", now: clock, handle: async () => {},
  })).claimed, 0);
});

test("programme une reprise bornee sans conserver le message d'erreur", async () => {
  const repository = await seededRepository();
  const times = [
    new Date("2026-08-12T10:02:00.000Z"),
    new Date("2026-08-12T10:02:01.000Z"),
  ];
  const result = await consumeNotificationEvents({
    repository, workerId: "notification-worker-1", now: () => times.shift(),
    handle: async () => { const error = new Error("detail sensible a ne pas persister"); error.code = "template_unavailable"; throw error; },
  });
  assert.equal(result.retried, 1);
  const stored = repository.getNotificationEvent(applicationId, eventId);
  assert.equal(stored.status, "retry");
  assert.equal(stored.lastErrorCode, "template_unavailable");
  assert.equal(stored.availableAt, "2026-08-12T10:02:31.000Z");
  assert.doesNotMatch(JSON.stringify(stored), /detail sensible/);
});

test("met en quarantaine apres le nombre maximal de tentatives", async () => {
  const repository = await seededRepository();
  let current = new Date("2026-08-12T10:02:00.000Z");
  const now = () => {
    const value = current;
    current = new Date(current.valueOf() + 60 * 60_000);
    return value;
  };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const result = await consumeNotificationEvents({
      repository, workerId: "notification-worker-1", now, maxAttempts: 3,
      handle: async () => { throw Object.assign(new Error("echec"), { code: "render_failed" }); },
    });
    assert.equal(result[attempt === 3 ? "quarantined" : "retried"], 1);
  }
  const stored = repository.getNotificationEvent(applicationId, eventId);
  assert.equal(stored.status, "quarantined");
  assert.equal(stored.processingAttempts, 3);
  assert.equal(stored.lastErrorCode, "render_failed");
  assert.equal((await consumeNotificationEvents({
    repository, workerId: "notification-worker-1", now, handle: async () => {},
  })).claimed, 0);
});

test("borne le delai exponentiel de reprise", () => {
  assert.equal(notificationRetryDelayMs(1), 30_000);
  assert.equal(notificationRetryDelayMs(2), 60_000);
  assert.equal(notificationRetryDelayMs(20), 60 * 60_000);
});
