import { createHumanIdentityPreprod } from "./human-identity-preprod.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await createHumanIdentityPreprod(repository, {
      database: databaseConfig.database,
      allowCreation: process.env.N09_ALLOW_HUMAN_IDENTITY_PREPROD_CREATE,
      operatorIdentityId: process.env.N09_OPERATOR_IDENTITY_ID,
      email: process.env.N09_HUMAN_IDENTITY_EMAIL,
      displayName: process.env.N09_HUMAN_IDENTITY_DISPLAY_NAME,
      justification: process.env.N09_HUMAN_IDENTITY_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    const assignments = (await repository.listAllAssignments())
      .filter((item) => item.subjectId === result.identityId && item.status === "active");
    if (assignments.length !== 0) throw new Error("new human identity unexpectedly received access assignments");
    console.log(JSON.stringify({
      event: "human_identity_preproduction_completed",
      database: databaseConfig.database,
      identity_id: result.identityId,
      created: result.created,
      active_assignments: 0,
      correlation_id: result.correlationId,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "human_identity_preproduction_failed" }));
  process.exitCode = 1;
});
