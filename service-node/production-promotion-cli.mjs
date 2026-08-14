import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validateProductionPromotionManifest } from "./production-promotion.mjs";

async function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath || process.argv.length !== 3) throw new Error("one production promotion manifest is required");
  const manifest = JSON.parse(await readFile(resolve(manifestPath), "utf8"));
  const result = validateProductionPromotionManifest(manifest);
  console.log(JSON.stringify({
    event: "production_promotion_ready",
    ready: result.ready,
    schema_version: result.schemaVersion,
    change_id: result.changeId,
    manifest_sha256: result.manifestHash,
    components: result.components.map(({ applicationId, commit, artifactSha256 }) => ({
      application_id: applicationId,
      commit,
      artifact_sha256: artifactSha256,
    })),
  }));
}

main().catch(() => {
  console.error(JSON.stringify({ event: "production_promotion_refused", ready: false }));
  process.exitCode = 1;
});
