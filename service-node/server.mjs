import { createServer } from "node:http";
import { createAdministrationSessionAuthority } from "./administration-session-authority.mjs";
import {
  createApplicationSessionAuthority, createCompositeApplicationSessionAuthority,
} from "./application-session-authority.mjs";
import { createHttpHandler } from "./http.mjs";
import { createInternalClientAuthenticator, internalClientsFromEnvironment } from "./internal-client-auth.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import {
  administrationSessionConfigFromEnvironment, energyApplicationSessionConfigFromEnvironment,
  httpConfigFromEnvironment, mariaDbConfigFromEnvironment,
  portalApplicationSessionConfigFromEnvironment, tasksApplicationSessionConfigFromEnvironment,
} from "./runtime-config.mjs";
import { oidcConfigFromEnvironment } from "./oidc.mjs";
import { createPersonalSessionManagement } from "./personal-session-management.mjs";
import { createOperatorSessionManagement } from "./operator-session-management.mjs";
import { createIdentityStateManagement } from "./identity-state-management.mjs";
import { portalOriginsFromEnvironment } from "./portal-session-broker.mjs";
import { createEmailLoginDelivery, emailLoginConfigFromEnvironment } from "./email-login.mjs";
import { createNotificationWorkerLoop } from "./notification-worker-loop.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const httpConfig = httpConfigFromEnvironment(process.env);
  const oidcConfig = oidcConfigFromEnvironment(process.env);
  const administrationSessionConfig = administrationSessionConfigFromEnvironment(process.env);
  const tasksSessionConfig = tasksApplicationSessionConfigFromEnvironment(process.env);
  const energySessionConfig = energyApplicationSessionConfigFromEnvironment(process.env);
  const portalSessionConfig = portalApplicationSessionConfigFromEnvironment(process.env);
  const portalOrigins = portalOriginsFromEnvironment(process.env);
  const emailLoginConfig = emailLoginConfigFromEnvironment(process.env);
  const emailLoginDelivery = createEmailLoginDelivery(emailLoginConfig);
  const notificationWorkers = createNotificationWorkerLoop({ environment: process.env });
  const authenticate = createInternalClientAuthenticator({ clients: internalClientsFromEnvironment(process.env) });
  const pool = await createMariaDbPool(databaseConfig);
  await pool.query("SELECT 1");

  const repository = new MariaDbRepository(pool);
  const administrationSessionAuthority = createAdministrationSessionAuthority({
    repository,
    config: administrationSessionConfig,
  });
  const sessionAuthority = createCompositeApplicationSessionAuthority([
    createApplicationSessionAuthority({ repository, config: tasksSessionConfig }),
    createApplicationSessionAuthority({ repository, config: energySessionConfig }),
    createApplicationSessionAuthority({ repository, config: portalSessionConfig }),
  ]);
  const personalSessionManagement = createPersonalSessionManagement({ repository });
  const operatorSessionManagement = createOperatorSessionManagement({ repository });
  const identityStateManagement = createIdentityStateManagement({ repository });
  const server = createServer(createHttpHandler({
    repository,
    oidcConfig,
    authenticate,
    administrationSessionAuthority,
    sessionAuthority,
    personalSessionManagement,
    operatorSessionManagement,
    identityStateManagement,
    portalOrigins,
    emailLogin: emailLoginConfig.enabled
      ? { ...emailLoginConfig, delivery: emailLoginDelivery }
      : { enabled: false },
  }));
  server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));

  const stop = async () => {
    await notificationWorkers?.stop();
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(httpConfig.port, httpConfig.host, resolve);
  });
  console.log(JSON.stringify({
    event: "service_started", host: httpConfig.host, port: httpConfig.port,
    administration_session_mode: administrationSessionConfig.mode,
    tasks_session_mode: tasksSessionConfig.mode,
    energy_session_mode: energySessionConfig.mode,
    portal_session_mode: portalSessionConfig.mode,
    email_login_enabled: emailLoginConfig.enabled,
  }));
  notificationWorkers?.start();
}

main().catch(() => {
  console.error(JSON.stringify({ event: "service_start_failed" }));
  process.exitCode = 1;
});
