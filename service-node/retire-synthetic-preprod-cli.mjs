import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { retireSyntheticPreprod } from "./retire-synthetic-preprod.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await retireSyntheticPreprod(repository, {
      database: databaseConfig.database,
      allowRetirement: process.env.N09_ALLOW_SYNTHETIC_RETIREMENT,
      operatorIdentityId: process.env.N09_OPERATOR_IDENTITY_ID,
      justification: process.env.N09_SYNTHETIC_RETIREMENT_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "synthetic_preproduction_retirement_completed", database: databaseConfig.database,
      changed: result.changed, correlation_id: result.correlationId, audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "synthetic_preproduction_retirement_failed" }));
  process.exitCode = 1;
});
