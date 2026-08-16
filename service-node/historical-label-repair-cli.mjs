import { repairHistoricalLabels } from "./historical-label-repair.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const apply = process.env.N09_APPLY_HISTORICAL_LABEL_REPAIR === "true";
    const result = await repairHistoricalLabels(repository, {
      database: databaseConfig.database,
      apply,
      allowRepair: process.env.N09_ALLOW_HISTORICAL_LABEL_REPAIR,
      operatorIdentityId: process.env.N09_OPERATOR_IDENTITY_ID,
      justification: process.env.N09_HISTORICAL_LABEL_REPAIR_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: apply ? "historical_label_repair_completed" : "historical_label_repair_planned",
      database: databaseConfig.database,
      ...result,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "historical_label_repair_failed" }));
  process.exitCode = 1;
});
