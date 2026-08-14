import assert from "node:assert/strict";
import test from "node:test";
import { validateProductionPromotionManifest } from "./production-promotion.mjs";

const digest = (character) => character.repeat(64);
const now = new Date("2026-08-14T08:00:00.000Z");

function component({ applicationId, repository, origin, healthPath, database, commit, node, python }) {
  return {
    application_id: applicationId,
    repository,
    origin,
    health_path: healthPath,
    database,
    commit,
    artifact_sha256: digest(applicationId === "n09-administration" ? "a" : "b"),
    release: `releases/${commit.slice(0, 7)}`,
    tests: { node, python, report_sha256: digest("c") },
    backup: {
      path: `/srv/customer/backups/production-${applicationId}/before-${commit.slice(0, 7)}.sql.gz`,
      sha256: digest("d"),
      restore_tested_at: "2026-08-14T07:00:00.000Z",
      restore_proof_sha256: digest("e"),
    },
    rollback: { release: "releases/3333333", procedure_sha256: digest("f") },
  };
}

function manifest() {
  return {
    schema_version: 1,
    change_id: "N09-PROD-20260814-001",
    approved_by_identity_id: "10000000-0000-4000-8000-000000000001",
    approved_at: "2026-08-14T07:30:00.000Z",
    window: { starts_at: "2026-08-14T08:30:00.000Z", ends_at: "2026-08-14T10:30:00.000Z" },
    components: [
      component({
        applicationId: "n09-administration",
        repository: "NSK-Tech-09/N09-Administration",
        origin: "https://admin.nsktech.fr",
        healthPath: "/health",
        database: "n09_admin_prod",
        commit: "1".repeat(40),
        node: 250,
        python: 63,
      }),
      component({
        applicationId: "n09-suivi-taches",
        repository: "NSK-Tech-09/N09-Suivi-des-taches",
        origin: "https://taches.nsktech.fr",
        healthPath: "/api/health",
        database: "n09_tasks_prod",
        commit: "2".repeat(40),
        node: 213,
        python: 0,
      }),
    ],
    safeguards: {
      same_artifacts_as_preproduction: true,
      production_databases_isolated: true,
      secrets_staged_outside_repository: true,
      dns_and_tls_ready: true,
      legacy_sessions_invalidation_planned: true,
      external_notifications_enabled: false,
      energie_unchanged: true,
    },
  };
}

test("scelle un Go production complet sans exposer de secret", () => {
  const result = validateProductionPromotionManifest(manifest(), { now });
  assert.equal(result.ready, true);
  assert.equal(result.changeId, "N09-PROD-20260814-001");
  assert.match(result.manifestHash, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.components.map((item) => item.applicationId), [
    "n09-administration", "n09-suivi-taches",
  ]);
});

test("produit une empreinte stable indépendamment de l'ordre des clés", () => {
  const first = manifest();
  const second = { safeguards: first.safeguards, components: first.components, window: first.window,
    approved_at: first.approved_at, approved_by_identity_id: first.approved_by_identity_id,
    change_id: first.change_id, schema_version: first.schema_version };
  assert.equal(
    validateProductionPromotionManifest(first, { now }).manifestHash,
    validateProductionPromotionManifest(second, { now }).manifestHash,
  );
});

test("refuse un secret ou une valeur factice dans le manifeste", () => {
  const withSecret = manifest();
  withSecret.client_secret = "sensible";
  assert.throws(() => validateProductionPromotionManifest(withSecret, { now }), /secret-bearing/);
  const withCredential = manifest();
  withCredential.api_key = "sensible";
  assert.throws(() => validateProductionPromotionManifest(withCredential, { now }), /secret-bearing/);
  const placeholder = manifest();
  placeholder.components[0].origin = "https://example.invalid";
  assert.throws(() => validateProductionPromotionManifest(placeholder, { now }), /placeholder/);
});

test("refuse tout champ alternatif ou valeur non canonique", () => {
  const extra = manifest();
  extra.note = "information non opposable";
  assert.throws(() => validateProductionPromotionManifest(extra, { now }), /manifest fields/);
  const whitespace = manifest();
  whitespace.components[0].database = "n09_admin_prod ";
  assert.throws(() => validateProductionPromotionManifest(whitespace, { now }), /canonical/);
});

test("refuse une origine, une base ou un chemin de santé de préproduction", () => {
  for (const mutate of [
    (value) => { value.components[0].origin = "https://preprod-admin.nsktech.fr"; },
    (value) => { value.components[0].database = "n09_admin_preprod"; },
    (value) => { value.components[1].health_path = "/health"; },
  ]) {
    const value = manifest();
    mutate(value);
    assert.throws(() => validateProductionPromotionManifest(value, { now }));
  }
});

test("refuse un artefact mutable ou une release reconstruite", () => {
  const shortCommit = manifest();
  shortCommit.components[0].commit = "1".repeat(7);
  assert.throws(() => validateProductionPromotionManifest(shortCommit, { now }), /commit/);
  const rebuilt = manifest();
  rebuilt.components[0].release = "releases/2222222";
  assert.throws(() => validateProductionPromotionManifest(rebuilt, { now }), /release/);
});

test("refuse une preuve de tests inférieure à la préproduction validée", () => {
  const value = manifest();
  value.components[0].tests.node = 249;
  assert.throws(() => validateProductionPromotionManifest(value, { now }), /test evidence/);
});

test("refuse une sauvegarde non restaurée ou un repli sur la release promue", () => {
  const futureRestore = manifest();
  futureRestore.components[0].backup.restore_tested_at = "2026-08-15T07:00:00.000Z";
  assert.throws(() => validateProductionPromotionManifest(futureRestore, { now }), /future/);
  const staleRestore = manifest();
  staleRestore.components[0].backup.restore_tested_at = "2026-06-01T07:00:00.000Z";
  assert.throws(() => validateProductionPromotionManifest(staleRestore, { now }), /too old/);
  const sameRelease = manifest();
  sameRelease.components[0].rollback.release = sameRelease.components[0].release;
  assert.throws(() => validateProductionPromotionManifest(sameRelease, { now }), /rollback/);
});

test("exige Administration et Suivi des tâches une seule fois chacun", () => {
  const value = manifest();
  value.components[1] = structuredClone(value.components[0]);
  assert.throws(() => validateProductionPromotionManifest(value, { now }), /unique and complete/);
});

test("refuse une décision tardive, une fenêtre expirée ou trop longue", () => {
  const lateApproval = manifest();
  lateApproval.approved_at = "2026-08-14T09:00:00.000Z";
  assert.throws(() => validateProductionPromotionManifest(lateApproval, { now }), /window/);
  const futureApproval = manifest();
  futureApproval.approved_at = "2026-08-14T08:15:00.000Z";
  assert.throws(() => validateProductionPromotionManifest(futureApproval, { now }), /window/);
  const expired = manifest();
  assert.throws(() => validateProductionPromotionManifest(expired, { now: new Date("2026-08-14T11:00:00.000Z") }), /expired/);
  const tooLong = manifest();
  tooLong.window.ends_at = "2026-08-14T13:00:00.000Z";
  assert.throws(() => validateProductionPromotionManifest(tooLong, { now }), /window/);
});

test("maintient les canaux externes fermés et N09 Energie hors périmètre", () => {
  const external = manifest();
  external.safeguards.external_notifications_enabled = true;
  assert.throws(() => validateProductionPromotionManifest(external, { now }), /notification/);
  const energie = manifest();
  energie.safeguards.energie_unchanged = false;
  assert.throws(() => validateProductionPromotionManifest(energie, { now }), /Energie/);
});
