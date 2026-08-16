import assert from "node:assert/strict";
import test from "node:test";
import {
  consumeNotificationEmailDeliveries, createNotificationEmailDelivery, notificationEmailDeliveryConfig,
} from "./notification-email-delivery.mjs";

const environment = {
  N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY: "true", N09_ENVIRONMENT: "production",
  N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE: "2026-08-16T08:00:00.000Z",
  N09_TASKS_PUBLIC_ORIGIN: "https://taches.nsktech.fr",
  N09_EMAIL_LOGIN_ENABLED: "true", N09_EMAIL_LOGIN_DELIVERY_PROVIDER: "brevo",
  N09_EMAIL_LOGIN_SENDER_EMAIL: "ne-pas-repondre@nsktech.fr",
  N09_EMAIL_LOGIN_SENDER_NAME: "NSK Tech 09", N09_EMAIL_LOGIN_BREVO_API_KEY: "x".repeat(32),
  N09_PUBLIC_ORIGIN: "https://prod-admin.nsktech.fr",
};

const item = {
  deliveryId: "d".repeat(64), notificationId: "n".repeat(64),
  recipientIdentityId: "00000000-0000-4000-8000-000000000001",
  recipientEmail: "f.travers@nsktech.fr", recipientDisplayName: "Fred <TRAVERS>",
  title: "Tâche mise à jour", message: "Une tâche a été mise à jour.",
  contextResourceId: "task_1", processingAttempts: 1,
};

test("ferme l’envoi par défaut et exige un coupe-circuit temporel exact", () => {
  assert.throws(() => notificationEmailDeliveryConfig({}), /disabled/);
  assert.throws(() => notificationEmailDeliveryConfig({
    ...environment, N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE: "2026-08-16",
  }), /NOT_BEFORE/);
  const config = notificationEmailDeliveryConfig(environment);
  assert.equal(config.tasksPublicOrigin, "https://taches.nsktech.fr");
  assert.equal(config.notBefore.toISOString(), "2026-08-16T08:00:00.000Z");
});

test("envoie par Brevo à l’identité professionnelle résolue au dernier moment", async () => {
  let request;
  const config = notificationEmailDeliveryConfig(environment);
  const delivery = createNotificationEmailDelivery(config, {
    fetchImpl: async (url, options) => { request = { url, options }; return { ok: true, status: 201 }; },
  });
  await delivery.send(item);
  assert.equal(request.url, "https://api.brevo.com/v3/smtp/email");
  assert.equal(request.options.headers["api-key"], "x".repeat(32));
  const body = JSON.parse(request.options.body);
  assert.equal(body.to[0].email, "f.travers@nsktech.fr");
  assert.match(body.textContent, /https:\/\/taches\.nsktech\.fr\/tasks\/task_1/);
  assert.match(body.htmlContent, /Fred &lt;TRAVERS&gt;/);
  assert.doesNotMatch(request.options.body, /api-key/);
});

test("acquitte l’envoi et ne persiste aucun détail secret", async () => {
  const calls = [];
  const repository = {
    claimNotificationEmailDeliveries: async (value) => { calls.push(["claim", value]); return [item]; },
    completeNotificationEmailDelivery: async (value) => calls.push(["complete", value]),
    failNotificationEmailDelivery: async (value) => calls.push(["fail", value]),
  };
  const result = await consumeNotificationEmailDeliveries({
    repository, delivery: { send: async (value) => calls.push(["send", value]) },
    workerId: "notification-email:test:1", limit: 20, maxAttempts: 5, leaseMs: 60_000,
    retryBaseMs: 60_000, notBefore: new Date("2026-08-16T08:00:00.000Z"),
    now: () => new Date("2026-08-16T08:01:00.000Z"),
  });
  assert.deepEqual(result, { claimed: 1, processed: 1, retried: 0, quarantined: 0 });
  assert.equal(calls.some(([name]) => name === "complete"), true);
  assert.doesNotMatch(JSON.stringify(calls.find(([name]) => name === "complete")), /f\.travers@/);
});

test("programme une reprise puis met en quarantaine sans fuite du message fournisseur", async () => {
  const failures = [];
  const repository = {
    claimNotificationEmailDeliveries: async () => [{ ...item, processingAttempts: failures.length ? 5 : 1 }],
    completeNotificationEmailDelivery: async () => {},
    failNotificationEmailDelivery: async (value) => failures.push(value),
  };
  const run = () => consumeNotificationEmailDeliveries({
    repository, delivery: { send: async () => { throw new Error("réponse fournisseur confidentielle"); } },
    workerId: "notification-email:test:2", limit: 20, maxAttempts: 5, leaseMs: 60_000,
    retryBaseMs: 60_000, notBefore: new Date("2026-08-16T08:00:00.000Z"),
    now: () => new Date("2026-08-16T08:01:00.000Z"),
  });
  assert.equal((await run()).retried, 1);
  assert.equal((await run()).quarantined, 1);
  assert.equal(failures[0].errorCode, "notification_email_delivery_failed");
  assert.doesNotMatch(JSON.stringify(failures), /confidentielle/);
});
