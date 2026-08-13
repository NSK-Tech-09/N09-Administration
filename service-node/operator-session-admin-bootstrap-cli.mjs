import { bootstrapOperatorSessionAdministrator } from "./operator-session-admin-bootstrap.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await bootstrapOperatorSessionAdministrator(repository, {
      database: databaseConfig.database,
      allowBootstrap: process.env.N09_ALLOW_OPERATOR_SESSION_BOOTSTRAP,
      identityId: process.env.N09_ADMIN_IDENTITY_ID,
      justification: process.env.N09_ADMIN_BOOTSTRAP_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "operator_session_bootstrap_completed",
      database: databaseConfig.database,
      identity_id: process.env.N09_ADMIN_IDENTITY_ID,
      created: result.created,
      correlation_id: result.correlationId,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "operator_session_bootstrap_failed" }));
  process.exitCode = 1;
});
