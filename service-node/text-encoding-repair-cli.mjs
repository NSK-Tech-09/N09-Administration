import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";
import { repairHistoricalTextEncoding } from "./text-encoding-repair.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const apply = process.env.N09_APPLY_TEXT_ENCODING_REPAIR === "true";
    const result = await repairHistoricalTextEncoding(repository, {
      database: databaseConfig.database,
      apply,
      allowRepair: process.env.N09_ALLOW_TEXT_ENCODING_REPAIR,
      confirmation: process.env.N09_TEXT_ENCODING_REPAIR_CONFIRMATION,
      operatorEmail: process.env.N09_TEXT_ENCODING_REPAIR_OPERATOR_EMAIL,
      justification: process.env.N09_TEXT_ENCODING_REPAIR_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: apply ? "text_encoding_repair_completed" : "text_encoding_repair_previewed",
      database: databaseConfig.database, ...result, audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ event: "text_encoding_repair_failed", reason: error?.message || "unexpected_error" }));
  process.exitCode = 1;
});
