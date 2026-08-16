import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const MANAGED_ENVIRONMENTS = new Set(["preprod", "production"]);

function intervalFromEnvironment(environment) {
  const intervalMs = Number(environment.N09_NOTIFICATION_WORKER_INTERVAL_MS || 60_000);
  if (!Number.isInteger(intervalMs) || intervalMs < 10_000 || intervalMs > 3_600_000) {
    throw new Error("invalid N09_NOTIFICATION_WORKER_INTERVAL_MS");
  }
  return intervalMs;
}

function runScript(script, { environment = process.env, spawnImpl = spawn } = {}) {
  const cwd = fileURLToPath(new URL("./", import.meta.url));
  return new Promise((resolve, reject) => {
    const child = spawnImpl(process.execPath, [script], {
      cwd, env: environment, stdio: ["ignore", "inherit", "inherit"],
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(Object.assign(new Error("notification worker command failed"), {
        code: "notification_worker_command_failed", exitCode: code, signal,
      }));
    });
  });
}

export function notificationWorkerLoopConfig(environment = process.env) {
  if (environment.N09_ALLOW_NOTIFICATION_PROCESSING !== "true") return null;
  if (!MANAGED_ENVIRONMENTS.has(environment.N09_ENVIRONMENT)) {
    throw new Error("notification worker loop requires a managed environment");
  }
  return Object.freeze({
    intervalMs: intervalFromEnvironment(environment),
    externalDelivery: environment.N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY === "true",
  });
}

export function createNotificationWorkerLoop({
  environment = process.env,
  run = (script) => runScript(script, { environment }),
  schedule = setInterval,
  unschedule = clearInterval,
  logger = console,
} = {}) {
  const config = notificationWorkerLoopConfig(environment);
  if (!config) return null;

  let timer = null;
  let active = null;
  let stopping = false;

  const cycle = async () => {
    if (stopping || active) return;
    active = (async () => {
      try {
        await run("notification-consumer-cli.mjs");
        if (config.externalDelivery) await run("notification-email-delivery-cli.mjs");
      } catch {
        logger.error(JSON.stringify({ event: "notification_worker_cycle_failed" }));
      } finally {
        active = null;
      }
    })();
    await active;
  };

  return Object.freeze({
    start() {
      if (timer || stopping) return;
      void cycle();
      timer = schedule(() => void cycle(), config.intervalMs);
      timer?.unref?.();
      logger.log(JSON.stringify({
        event: "notification_worker_started",
        interval_ms: config.intervalMs,
        external_delivery: config.externalDelivery,
      }));
    },
    async stop() {
      stopping = true;
      if (timer) unschedule(timer);
      timer = null;
      if (active) await active;
    },
    cycle,
  });
}
