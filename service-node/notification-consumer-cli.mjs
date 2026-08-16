import { hostname } from "node:os";
import { consumeNotificationEvents } from "./notification-consumer.mjs";
import {
  createNotificationEventHandler, createTasksNotificationResolverClient,
  notificationExternalDeliveryPolicy, tasksNotificationResolverConfig,
} from "./notification-materializer.mjs";
import {
  acquireNotificationProcessingLock, createMariaDbPool, MariaDbRepository,
} from "./mariadb.mjs";
import {
  notificationProcessingConfig, runNotificationProcessingCycle,
} from "./notification-processing-runner.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

const processing = notificationProcessingConfig(process.env);
const config = tasksNotificationResolverConfig(process.env);
if (!config) throw new Error("tasks notification resolver is not configured");
const pool = await createMariaDbPool(mariaDbConfigFromEnvironment(process.env));
try {
  const repository = new MariaDbRepository(pool);
  const workerId = `notification-consumer:${hostname()}:${process.pid}`;
  const result = await runNotificationProcessingCycle({
    workerId,
    acquireLock: () => acquireNotificationProcessingLock(pool),
    record: (outcome) => repository.recordNotificationProcessingRun(outcome),
    consume: () => consumeNotificationEvents({
      repository, workerId,
      handle: createNotificationEventHandler({
        repository, resolve: createTasksNotificationResolverClient({ config }),
        externalDeliveryPolicy: notificationExternalDeliveryPolicy(process.env),
      }),
      limit: processing.batchSize, maxAttempts: processing.maxAttempts, leaseMs: processing.leaseMs,
    }),
  });
  console.log(JSON.stringify(result));
} finally {
  await pool.end();
}
