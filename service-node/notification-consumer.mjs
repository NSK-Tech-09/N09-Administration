const ERROR_CODE = /^[a-z][a-z0-9_:-]{0,79}$/;

export function notificationRetryDelayMs(attempt) {
  if (!Number.isInteger(attempt) || attempt < 1) throw new Error("invalid_notification_attempt");
  return Math.min(60 * 60_000, 30_000 * (2 ** Math.min(attempt - 1, 7)));
}

function safeErrorCode(error) {
  const candidate = typeof error?.code === "string" ? error.code : "processing_failed";
  return ERROR_CODE.test(candidate) ? candidate : "processing_failed";
}

export async function consumeNotificationEvents({
  repository, workerId, handle, now = () => new Date(), limit = 20,
  leaseMs = 60_000, maxAttempts = 5,
}) {
  if (typeof workerId !== "string" || !/^[A-Za-z0-9._:-]{3,128}$/.test(workerId)) {
    throw new Error("invalid_notification_worker");
  }
  if (typeof handle !== "function") throw new Error("notification handler is required");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("invalid_notification_batch_limit");
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 20) throw new Error("invalid_notification_max_attempts");
  const claimedAt = now();
  const events = await repository.claimNotificationEvents({ workerId, limit, now: claimedAt, leaseMs });
  const result = { claimed: events.length, processed: 0, retried: 0, quarantined: 0 };
  for (const event of events) {
    try {
      await handle(event);
      await repository.completeNotificationEvent({
        sourceApplicationId: event.sourceApplicationId, eventId: event.eventId,
        workerId, processedAt: now(),
      });
      result.processed += 1;
    } catch (error) {
      const failedAt = now();
      const quarantined = event.processingAttempts >= maxAttempts;
      await repository.failNotificationEvent({
        sourceApplicationId: event.sourceApplicationId, eventId: event.eventId,
        workerId, failedAt, availableAt: quarantined
          ? failedAt : new Date(failedAt.valueOf() + notificationRetryDelayMs(event.processingAttempts)),
        errorCode: safeErrorCode(error), quarantined,
      });
      result[quarantined ? "quarantined" : "retried"] += 1;
    }
  }
  return result;
}
