import assert from "node:assert/strict";
import test from "node:test";
import { createNotificationWorkerLoop, notificationWorkerLoopConfig } from "./notification-worker-loop.mjs";

test("reste absent lorsque le traitement autonome est fermé", () => {
  assert.equal(notificationWorkerLoopConfig({ N09_ALLOW_NOTIFICATION_PROCESSING: "false" }), null);
  assert.equal(createNotificationWorkerLoop({
    environment: { N09_ALLOW_NOTIFICATION_PROCESSING: "false" },
  }), null);
});

test("refuse un environnement ou une cadence non gouvernés", () => {
  assert.throws(() => notificationWorkerLoopConfig({
    N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "local",
  }), /managed environment/);
  assert.throws(() => notificationWorkerLoopConfig({
    N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "production",
    N09_NOTIFICATION_WORKER_INTERVAL_MS: "9999",
  }), /WORKER_INTERVAL/);
});

test("enchaîne matérialisation puis courriel sans chevauchement", async () => {
  const calls = [];
  const scheduled = [];
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const loop = createNotificationWorkerLoop({
    environment: {
      N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "production",
      N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY: "true", N09_NOTIFICATION_WORKER_INTERVAL_MS: "10000",
    },
    run: async (script) => { calls.push(script); if (calls.length === 1) await gate; },
    schedule: (callback, interval) => { scheduled.push({ callback, interval }); return { unref() {} }; },
    unschedule: () => {},
    logger: { log() {}, error() {} },
  });
  loop.start();
  await new Promise((resolve) => setImmediate(resolve));
  scheduled[0].callback();
  assert.deepEqual(calls, ["notification-consumer-cli.mjs"]);
  release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, [
    "notification-consumer-cli.mjs", "notification-email-delivery-cli.mjs",
  ]);
  assert.equal(scheduled[0].interval, 10000);
  await loop.stop();
});

test("n'exécute pas le canal externe lorsque sa garde est fermée", async () => {
  const calls = [];
  const loop = createNotificationWorkerLoop({
    environment: {
      N09_ALLOW_NOTIFICATION_PROCESSING: "true", N09_ENVIRONMENT: "production",
      N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY: "false",
    },
    run: async (script) => calls.push(script),
    schedule: () => ({ unref() {} }), unschedule: () => {},
    logger: { log() {}, error() {} },
  });
  await loop.cycle();
  assert.deepEqual(calls, ["notification-consumer-cli.mjs"]);
  await loop.stop();
});
