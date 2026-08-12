import { hostname } from "node:os";
import { consumeNotificationEvents } from "./notification-consumer.mjs";
import {
  createNotificationEventHandler, createTasksNotificationResolverClient, tasksNotificationResolverConfig,
} from "./notification-materializer.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

if (process.env.N09_ALLOW_NOTIFICATION_PROCESSING !== "true") {
  throw new Error("notification processing is disabled");
}
const config = tasksNotificationResolverConfig(process.env);
if (!config) throw new Error("tasks notification resolver is not configured");
const pool = await createMariaDbPool(mariaDbConfigFromEnvironment(process.env));
try {
  const repository = new MariaDbRepository(pool);
  const result = await consumeNotificationEvents({
    repository,
    workerId: `notification-consumer:${hostname()}:${process.pid}`,
    handle: createNotificationEventHandler({
      repository, resolve: createTasksNotificationResolverClient({ config }),
    }),
    limit: Number(process.env.N09_NOTIFICATION_PROCESSING_BATCH_SIZE || 20),
    maxAttempts: Number(process.env.N09_NOTIFICATION_PROCESSING_MAX_ATTEMPTS || 5),
    leaseMs: Number(process.env.N09_NOTIFICATION_PROCESSING_LEASE_MS || 60_000),
  });
  console.log(JSON.stringify(result));
} finally {
  await pool.end();
}
