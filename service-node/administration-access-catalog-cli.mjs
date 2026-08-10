import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

async function main() {
  const databaseConfig = mariaDbConfigFromEnvironment(process.env);
  const pool = await createMariaDbPool(databaseConfig);
  try {
    const repository = new MariaDbRepository(pool);
    const result = await publishAdministrationAccessCatalog(repository, {
      database: databaseConfig.database,
      allowBootstrap: process.env.N09_ALLOW_ADMINISTRATION_CATALOG_BOOTSTRAP,
    });
    if (!await repository.verifyAuditChain()) throw new Error("audit chain verification failed");
    console.log(JSON.stringify({
      event: "administration_access_catalog_published", database: databaseConfig.database,
      created: result.created, catalog_version: result.catalogVersion, catalog_hash: result.catalogHash,
      correlation_id: result.correlationId, audit_chain_valid: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch(() => {
  console.error(JSON.stringify({ event: "administration_access_catalog_publication_failed" }));
  process.exitCode = 1;
});
