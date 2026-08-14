import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";
import { bootstrapEnergyProduction } from "./energy-production-bootstrap.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await bootstrapEnergyProduction(repository, {
      database: databaseConfig.database,
      allowBootstrap: process.env.N09_ALLOW_ENERGY_PRODUCTION_BOOTSTRAP,
      identityId: process.env.N09_ENERGY_OWNER_IDENTITY_ID,
      justification: process.env.N09_ENERGY_PRODUCTION_JUSTIFICATION,
      redirectUri: process.env.N09_ENERGY_LOGIN_REDIRECT_URI,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "energy_production_bootstrap_completed",
      database: databaseConfig.database,
      identity_id: process.env.N09_ENERGY_OWNER_IDENTITY_ID,
      created: result.created,
      correlation_id: result.correlationId,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "energy_production_bootstrap_failed" }));
  process.exitCode = 1;
});
