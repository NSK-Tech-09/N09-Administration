import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { grantResponsibleAuthority } from "./responsible-authority.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await grantResponsibleAuthority(repository, {
      database: databaseConfig.database,
      environment: process.env.N09_ENVIRONMENT,
      allowGrant: process.env.N09_ALLOW_LEGAL_OWNER_AUTHORITY,
      confirmation: process.env.N09_LEGAL_OWNER_AUTHORITY_CONFIRMATION,
      email: process.env.N09_LEGAL_OWNER_EMAIL,
      justification: process.env.N09_LEGAL_OWNER_AUTHORITY_JUSTIFICATION,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "legal_owner_authority_completed",
      correlation_id: result.correlationId,
      created_roles: result.created,
      unchanged_roles: result.unchanged,
      audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "legal_owner_authority_failed" }));
  process.exitCode = 1;
});
