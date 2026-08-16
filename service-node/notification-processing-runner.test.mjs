import assert from "node:assert/strict";
import test from "node:test";
import {
  notificationProcessingConfig, runNotificationProcessingCycle,
} from "./notification-processing-runner.mjs";

test("exige une activation explicite et accepte les deux environnements gouvernés", () => {
  assert.throws(() => notificationProcessingConfig({}), /disabled/);
  assert.throws(() => notificationProcessingConfig({
    N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "local",
  }), /managed environment/);
  assert.deepEqual(notificationProcessingConfig({
    N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "preprod",
    N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY: "false",
  }), { batchSize: 20, maxAttempts: 5, leaseMs: 60_000 });
  assert.deepEqual(notificationProcessingConfig({
    N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "production",
    N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY: "true",
  }), { batchSize: 20, maxAttempts: 5, leaseMs: 60_000 });
});

test("exécute et consigne exactement un cycle sous verrou", async () => {
  const calls = [];
  const times = [new Date("2026-08-12T20:00:00Z"), new Date("2026-08-12T20:00:01Z")];
  const result = await runNotificationProcessingCycle({
    workerId: "notification-consumer:test:1", now: () => times.shift(),
    acquireLock: async () => ({ release: async () => calls.push("release") }),
    consume: async () => ({ claimed: 3, processed: 2, retried: 1, quarantined: 0 }),
    record: async (outcome) => calls.push(outcome),
  });
  assert.deepEqual(result, { status: "succeeded", claimed: 3, processed: 2, retried: 1, quarantined: 0 });
  assert.equal(calls[0].status, "succeeded");
  assert.equal(calls[0].errorCode, null);
  assert.equal(calls[1], "release");
});

test("ignore sans effet un chevauchement", async () => {
  let consumed = false;
  const result = await runNotificationProcessingCycle({
    workerId: "notification-consumer:test:2", acquireLock: async () => null,
    consume: async () => { consumed = true; }, record: async () => { throw new Error("must not record"); },
  });
  assert.deepEqual(result, { status: "skipped_overlap" });
  assert.equal(consumed, false);
});

test("consigne un code borné et libère le verrou après une panne", async () => {
  const calls = [];
  const error = Object.assign(new Error("secret interne"), { code: "resolver_unavailable" });
  await assert.rejects(runNotificationProcessingCycle({
    workerId: "notification-consumer:test:3",
    acquireLock: async () => ({ release: async () => calls.push("release") }),
    consume: async () => { throw error; }, record: async (outcome) => calls.push(outcome),
  }), (caught) => caught === error);
  assert.equal(calls[0].status, "failed");
  assert.equal(calls[0].errorCode, "resolver_unavailable");
  assert.equal(calls[1], "release");
  assert.doesNotMatch(JSON.stringify(calls[0]), /secret interne/);
});
