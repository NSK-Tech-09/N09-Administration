import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";
import { assertSyntheticPreprodTarget, seedSyntheticPreprod } from "./synthetic-preprod.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  assertSyntheticPreprodTarget({
    database: databaseConfig.database,
    allowSyntheticPreprod: process.env.N09_ALLOW_SYNTHETIC_PREPROD,
  });
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await seedSyntheticPreprod(repository, {
      database: databaseConfig.database,
      allowSyntheticPreprod: process.env.N09_ALLOW_SYNTHETIC_PREPROD,
    });
    const auditChainValid = await repository.verifyAuditChain();
    if (!auditChainValid) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "synthetic_preproduction_seed_completed",
      database: databaseConfig.database,
      created: result.created,
      correlation_id: result.correlationId,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "synthetic_preproduction_seed_failed" }));
  process.exitCode = 1;
});
