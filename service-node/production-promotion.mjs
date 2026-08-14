import { createHash } from "node:crypto";

const COMPONENTS = Object.freeze({
  "n09-administration": Object.freeze({
    repository: "NSK-Tech-09/N09-Administration",
    origin: "https://admin.nsktech.fr",
    healthPath: "/health",
    minimumNodeTests: 250,
    minimumPythonTests: 63,
  }),
  "n09-suivi-taches": Object.freeze({
    repository: "NSK-Tech-09/N09-Suivi-des-taches",
    origin: "https://taches.nsktech.fr",
    healthPath: "/api/health",
    minimumNodeTests: 213,
    minimumPythonTests: 0,
  }),
});

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CHANGE_ID = /^N09-PROD-[0-9]{8}-[0-9]{3}$/;
const FORBIDDEN_KEY = /(^|_)(password|token|client_secret|session_secret|private_key|access_key|secret_key|api_key|credential)($|_)/i;
const PLACEHOLDER = /replace[-_ ]with|change[-_ ]me|example\.invalid|localhost/i;

function plainRecord(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function exactKeys(record, expected, name) {
  const actual = Object.keys(record).sort();
  const accepted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(accepted)) throw new Error(`${name} fields are invalid`);
}

function requiredString(record, name) {
  const value = record[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required`);
  if (value !== value.trim()) throw new Error(`${name} must be canonical`);
  return value;
}

function sha256(record, name) {
  const value = requiredString(record, name);
  if (!SHA256.test(value)) throw new Error(`${name} must be a SHA-256 digest`);
  return value;
}

function timestamp(record, name) {
  const value = requiredString(record, name);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString() !== value) {
    throw new Error(`${name} must be a canonical UTC timestamp`);
  }
  return parsed;
}

function nonNegativeInteger(record, name) {
  const value = record[name];
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  return value;
}

function assertNoSecretsOrPlaceholders(value, path = "manifest") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecretsOrPlaceholders(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (FORBIDDEN_KEY.test(key)) throw new Error(`secret-bearing field is forbidden at ${path}.${key}`);
      assertNoSecretsOrPlaceholders(item, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === "string" && PLACEHOLDER.test(value)) {
    throw new Error(`placeholder value is forbidden at ${path}`);
  }
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function validateTests(component, expected) {
  const tests = plainRecord(component.tests, "tests");
  exactKeys(tests, ["node", "python", "report_sha256"], "tests");
  const node = nonNegativeInteger(tests, "node");
  const python = nonNegativeInteger(tests, "python");
  sha256(tests, "report_sha256");
  if (node < expected.minimumNodeTests || python < expected.minimumPythonTests) {
    throw new Error(`insufficient test evidence for ${component.application_id}`);
  }
}

function validateBackup(component, now) {
  const backup = plainRecord(component.backup, "backup");
  exactKeys(backup, ["path", "sha256", "restore_tested_at", "restore_proof_sha256"], "backup");
  const path = requiredString(backup, "path");
  if (!path.startsWith("/srv/customer/backups/production-")) {
    throw new Error(`production backup path is invalid for ${component.application_id}`);
  }
  sha256(backup, "sha256");
  sha256(backup, "restore_proof_sha256");
  const restoredAt = timestamp(backup, "restore_tested_at");
  if (restoredAt > now) throw new Error(`restore proof is dated in the future for ${component.application_id}`);
  if (now - restoredAt > 30 * 24 * 60 * 60_000) {
    throw new Error(`restore proof is too old for ${component.application_id}`);
  }
}

function validateRollback(component, commit) {
  const rollback = plainRecord(component.rollback, "rollback");
  exactKeys(rollback, ["release", "procedure_sha256"], "rollback");
  const release = requiredString(rollback, "release");
  if (!/^releases\/[0-9a-f]{7,40}$/.test(release) || release === `releases/${commit.slice(0, 7)}`) {
    throw new Error(`rollback release is invalid for ${component.application_id}`);
  }
  sha256(rollback, "procedure_sha256");
}

function validateComponent(component, now) {
  plainRecord(component, "component");
  exactKeys(component, [
    "application_id", "repository", "origin", "health_path", "database", "commit",
    "artifact_sha256", "release", "tests", "backup", "rollback",
  ], "component");
  const applicationId = requiredString(component, "application_id");
  const expected = COMPONENTS[applicationId];
  if (!expected) throw new Error(`unsupported production component: ${applicationId}`);
  if (requiredString(component, "repository") !== expected.repository) {
    throw new Error(`repository mismatch for ${applicationId}`);
  }
  if (requiredString(component, "origin") !== expected.origin) {
    throw new Error(`production origin mismatch for ${applicationId}`);
  }
  if (requiredString(component, "health_path") !== expected.healthPath) {
    throw new Error(`health path mismatch for ${applicationId}`);
  }
  const database = requiredString(component, "database");
  if (!/^[a-z0-9_]+_prod$/.test(database) || database.includes("preprod")) {
    throw new Error(`production database is not isolated for ${applicationId}`);
  }
  const commit = requiredString(component, "commit");
  if (!COMMIT.test(commit)) throw new Error(`commit must be immutable for ${applicationId}`);
  sha256(component, "artifact_sha256");
  const release = requiredString(component, "release");
  if (release !== `releases/${commit.slice(0, 7)}`) throw new Error(`release does not match commit for ${applicationId}`);
  validateTests(component, expected);
  validateBackup(component, now);
  validateRollback(component, commit);
  return applicationId;
}

function validateSafeguards(manifest) {
  const safeguards = plainRecord(manifest.safeguards, "safeguards");
  const requiredTrue = [
    "same_artifacts_as_preproduction",
    "production_databases_isolated",
    "secrets_staged_outside_repository",
    "dns_and_tls_ready",
    "legacy_sessions_invalidation_planned",
  ];
  exactKeys(safeguards, [
    ...requiredTrue, "external_notifications_enabled", "energie_unchanged",
  ], "safeguards");
  for (const name of requiredTrue) {
    if (safeguards[name] !== true) throw new Error(`production safeguard is not satisfied: ${name}`);
  }
  if (safeguards.external_notifications_enabled !== false) {
    throw new Error("external notification delivery must remain disabled");
  }
  if (safeguards.energie_unchanged !== true) throw new Error("N09 Energie must remain unchanged");
}

export function validateProductionPromotionManifest(manifest, { now = new Date() } = {}) {
  plainRecord(manifest, "manifest");
  if (!(now instanceof Date) || !Number.isFinite(now.valueOf())) throw new Error("invalid validation time");
  assertNoSecretsOrPlaceholders(manifest);
  exactKeys(manifest, [
    "schema_version", "change_id", "approved_by_identity_id", "approved_at",
    "window", "components", "safeguards",
  ], "manifest");
  if (manifest.schema_version !== 1) throw new Error("unsupported production promotion schema");
  const changeId = requiredString(manifest, "change_id");
  if (!CHANGE_ID.test(changeId)) throw new Error("invalid production change identifier");
  const approvedBy = requiredString(manifest, "approved_by_identity_id");
  if (!UUID.test(approvedBy)) throw new Error("invalid approving identity");
  const approvedAt = timestamp(manifest, "approved_at");
  const window = plainRecord(manifest.window, "window");
  exactKeys(window, ["starts_at", "ends_at"], "window");
  const startsAt = timestamp(window, "starts_at");
  const endsAt = timestamp(window, "ends_at");
  if (approvedAt > now || approvedAt > startsAt || startsAt >= endsAt || endsAt - startsAt > 4 * 60 * 60_000) {
    throw new Error("invalid production change window");
  }
  if (endsAt <= now) throw new Error("production change window has expired");
  if (!Array.isArray(manifest.components) || manifest.components.length !== Object.keys(COMPONENTS).length) {
    throw new Error("the two production components are required");
  }
  const componentIds = manifest.components.map((component) => validateComponent(component, now));
  if (new Set(componentIds).size !== componentIds.length ||
      Object.keys(COMPONENTS).some((applicationId) => !componentIds.includes(applicationId))) {
    throw new Error("production components must be unique and complete");
  }
  validateSafeguards(manifest);
  const manifestHash = createHash("sha256").update(canonical(manifest), "utf8").digest("hex");
  return Object.freeze({
    ready: true,
    schemaVersion: 1,
    changeId,
    manifestHash,
    components: Object.freeze(manifest.components.map((component) => Object.freeze({
      applicationId: component.application_id,
      commit: component.commit,
      artifactSha256: component.artifact_sha256,
    }))),
  });
}
