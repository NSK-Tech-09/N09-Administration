const WORKER_ID = /^[A-Za-z0-9._:-]{3,128}$/;
const ERROR_CODE = /^[a-z][a-z0-9_:-]{0,79}$/;

function safeErrorCode(error) {
  const candidate = typeof error?.code === "string" ? error.code : "processing_cycle_failed";
  return ERROR_CODE.test(candidate) ? candidate : "processing_cycle_failed";
}

export function notificationProcessingConfig(environment = process.env) {
  if (environment.N09_ALLOW_NOTIFICATION_PROCESSING !== "true") {
    throw new Error("notification processing is disabled");
  }
  if (environment.N09_ENVIRONMENT !== "preprod") {
    throw new Error("autonomous notification processing is preproduction-only");
  }
  if (environment.N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY !== "false") {
    throw new Error("external notification delivery must remain disabled");
  }
  const integer = (name, fallback, minimum, maximum) => {
    const value = Number(environment[name] || fallback);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
      throw new Error(`invalid ${name}`);
    }
    return value;
  };
  return Object.freeze({
    batchSize: integer("N09_NOTIFICATION_PROCESSING_BATCH_SIZE", 20, 1, 100),
    maxAttempts: integer("N09_NOTIFICATION_PROCESSING_MAX_ATTEMPTS", 5, 1, 20),
    leaseMs: integer("N09_NOTIFICATION_PROCESSING_LEASE_MS", 60_000, 1_000, 3_600_000),
  });
}

export async function runNotificationProcessingCycle({
  workerId, acquireLock, consume, record, now = () => new Date(),
}) {
  if (typeof workerId !== "string" || !WORKER_ID.test(workerId)) {
    throw new Error("invalid_notification_worker");
  }
  if (typeof acquireLock !== "function" || typeof consume !== "function" || typeof record !== "function") {
    throw new Error("invalid notification processing runner");
  }
  const lock = await acquireLock();
  if (!lock) return Object.freeze({ status: "skipped_overlap" });
  if (typeof lock.release !== "function") throw new Error("invalid notification processing lock");

  const startedAt = now();
  let outcome;
  let processingError = null;
  try {
    try {
      const result = await consume();
      outcome = {
        status: "succeeded", startedAt, finishedAt: now(), errorCode: null,
        claimed: Number(result.claimed), processed: Number(result.processed),
        retried: Number(result.retried), quarantined: Number(result.quarantined),
      };
    } catch (error) {
      processingError = error;
      outcome = {
        status: "failed", startedAt, finishedAt: now(), errorCode: safeErrorCode(error),
        claimed: 0, processed: 0, retried: 0, quarantined: 0,
      };
    }
    await record(outcome);
  } finally {
    await lock.release();
  }
  if (processingError) throw processingError;
  return Object.freeze({
    status: outcome.status, claimed: outcome.claimed, processed: outcome.processed,
    retried: outcome.retried, quarantined: outcome.quarantined,
  });
}
