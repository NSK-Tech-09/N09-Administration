import { hostname } from "node:os";
import { createMariaDbPool, MariaDbRepository, acquireNotificationEmailDeliveryLock } from "./mariadb.mjs";
import {
  consumeNotificationEmailDeliveries, createNotificationEmailDelivery, notificationEmailDeliveryConfig,
} from "./notification-email-delivery.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

const config = notificationEmailDeliveryConfig(process.env);
const pool = await createMariaDbPool(mariaDbConfigFromEnvironment(process.env));
try {
  const lock = await acquireNotificationEmailDeliveryLock(pool);
  if (!lock) {
    console.log(JSON.stringify({ status: "skipped_overlap" }));
  } else {
    try {
      const result = await consumeNotificationEmailDeliveries({
        repository: new MariaDbRepository(pool), delivery: createNotificationEmailDelivery(config),
        workerId: `notification-email:${hostname()}:${process.pid}`,
        limit: config.batchSize, maxAttempts: config.maxAttempts, leaseMs: config.leaseMs,
        retryBaseMs: config.retryBaseMs, notBefore: config.notBefore,
      });
      console.log(JSON.stringify({ status: "succeeded", ...result }));
    } finally {
      await lock.release();
    }
  }
} finally {
  await pool.end();
}
