import assert from "node:assert/strict";
import test from "node:test";
import {
  createNotificationEventHandler, createTasksNotificationResolverClient,
  NotificationMaterializationError, tasksNotificationResolverConfig,
} from "./notification-materializer.mjs";

const event = {
  sourceApplicationId: "n09-suivi-taches", eventId: "event_abcdef0123456789abcd",
  eventType: "task.archived", eventHash: "a".repeat(64), taskId: "task_1", siteId: "site_1",
  actorId: "user_1", aggregateId: "task_1", payload: { task_version: 2 },
  occurredAt: "2026-08-12T10:00:00.000Z",
};

const responseBody = (changes = {}) => ({
  contract_version: 1,
  event_id: event.eventId,
  policy_version: "tasks-notification-policy-v1",
  intents: [{
    recipient_identity_id: "00000000-0000-4000-8000-000000000001",
    category: "task_activity", importance: "information", title: "Tâche archivée",
    message: "Une tâche a été archivée dans N09 – Suivi des tâches.",
    context: { application_id: "n09-suivi-taches", resource_type: "task", resource_id: "task_1" },
    requested_channels: ["in_app", "email", "push"],
  }],
  suppressed: { own_action: 1, preferences: 0, unlinked_identity: 0 },
  ...changes,
});

test("signe la résolution et valide strictement sa réponse", async () => {
  let request;
  const resolve = createTasksNotificationResolverClient({
    config: {
      origin: "https://preprod-taches.example.test", clientId: "admin-preprod",
      secret: "a-protected-test-secret-with-at-least-32-characters", timeoutMs: 1000,
    },
    now: () => 1_786_358_400_000,
    createNonce: () => "00000000-0000-4000-8000-000000000009",
    fetchImpl: async (_url, options) => {
      request = options;
      return { status: 200, json: async () => responseBody() };
    },
  });
  const resolution = await resolve(event);
  assert.equal(resolution.intents[0].recipientIdentityId, "00000000-0000-4000-8000-000000000001");
  assert.equal(request.headers["x-n09-client-id"], "admin-preprod");
  assert.match(request.headers["x-n09-signature"], /^[0-9a-f]{64}$/);
  assert.doesNotMatch(request.body, /@|password|secret|token/i);
});

test("matérialise l'interne et bloque chaque canal externe sans expédition", async () => {
  let stored;
  const repository = {
    async materializeNotificationResolution(value) { stored = value; return { created: true }; },
  };
  const handle = createNotificationEventHandler({
    repository,
    resolve: async () => ({
      policyVersion: "tasks-notification-policy-v1",
      intents: [{
        recipientIdentityId: "00000000-0000-4000-8000-000000000001",
        category: "task_activity", importance: "information", title: "Tâche archivée",
        message: "Une tâche a été archivée dans N09 – Suivi des tâches.",
        context: { applicationId: "n09-suivi-taches", resourceType: "task", resourceId: "task_1" },
        requestedChannels: ["in_app", "email", "push"],
      }],
      suppressed: { own_action: 1, preferences: 0, unlinked_identity: 0 },
    }),
    now: () => new Date("2026-08-12T10:02:00.000Z"),
  });
  await handle(event);
  assert.equal(stored.notifications.length, 1);
  assert.deepEqual(stored.externalDeliveries.map(({ channel, status, blockedReason }) =>
    ({ channel, status, blockedReason })), [
    { channel: "email", status: "blocked", blockedReason: "channel_not_enabled" },
    { channel: "push", status: "blocked", blockedReason: "channel_not_enabled" },
  ]);
  assert.match(stored.resolutionHash, /^[0-9a-f]{64}$/);
  assert.equal(stored.auditEvent.new_value.external_deliveries_blocked, 2);
});

test("conserve la même empreinte après une coupure entre matérialisation et acquittement", async () => {
  const hashes = [];
  const repository = {
    async materializeNotificationResolution(value) { hashes.push(value.resolutionHash); return { created: hashes.length === 1 }; },
  };
  const instants = [new Date("2026-08-12T10:02:00.000Z"), new Date("2026-08-12T10:05:00.000Z")];
  const handle = createNotificationEventHandler({
    repository,
    resolve: async () => ({
      policyVersion: "tasks-notification-policy-v1",
      intents: [{
        recipientIdentityId: "00000000-0000-4000-8000-000000000001",
        category: "task_activity", importance: "information", title: "Tâche archivée",
        message: "Une tâche a été archivée dans N09 – Suivi des tâches.",
        context: { applicationId: "n09-suivi-taches", resourceType: "task", resourceId: "task_1" },
        requestedChannels: ["in_app", "email"],
      }],
      suppressed: { own_action: 0, preferences: 0, unlinked_identity: 0 },
    }),
    now: () => instants.shift(),
  });
  await handle(event);
  await handle(event);
  assert.equal(hashes.length, 2);
  assert.equal(hashes[0], hashes[1]);
});

test("refuse une réponse qui injecte une adresse ou un contexte incohérent", async () => {
  const client = (body) => createTasksNotificationResolverClient({
    config: { origin: "https://tasks.test", clientId: "admin", secret: "x".repeat(32), timeoutMs: 1000 },
    fetchImpl: async () => ({ status: 200, json: async () => body }),
  });
  const withAddress = responseBody();
  withAddress.intents[0].message = "Écrire à personne@example.test";
  await assert.rejects(() => client(withAddress)(event), (error) =>
    error instanceof NotificationMaterializationError && error.code === "sensitive_notification_content");
  const mismatch = responseBody();
  mismatch.intents[0].context.resource_id = "task_2";
  await assert.rejects(() => client(mismatch)(event), (error) =>
    error instanceof NotificationMaterializationError && error.code === "notification_context_mismatch");
});

test("exige HTTPS, un secret distinct et une garde explicite de traitement", () => {
  assert.equal(tasksNotificationResolverConfig({}), null);
  assert.throws(() => tasksNotificationResolverConfig({
    N09_TASKS_NOTIFICATION_RESOLVER_ORIGIN: "http://tasks.test",
    N09_TASKS_NOTIFICATION_RESOLVER_CLIENT_ID: "admin",
    N09_TASKS_NOTIFICATION_RESOLVER_CLIENT_SECRET: "x".repeat(32),
  }), /HTTPS/);
});
