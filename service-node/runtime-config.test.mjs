import assert from "node:assert/strict";
import test from "node:test";
import {
  administrationSessionConfigFromEnvironment, httpConfigFromEnvironment, mariaDbConfigFromEnvironment,
  tasksApplicationSessionConfigFromEnvironment,
} from "./runtime-config.mjs";

const databaseEnvironment = {
  N09_DB_HOST: "database.internal",
  N09_DB_PORT: "3306",
  N09_DB_USER: "n09-runtime",
  N09_DB_PASSWORD: "not-a-real-secret",
  N09_DB_NAME: "n09_admin_preprod",
  N09_DB_SSL: "true",
};

test("charge une configuration MariaDB TLS sans exposer de valeur implicite", () => {
  assert.deepEqual(mariaDbConfigFromEnvironment(databaseEnvironment), {
    host: "database.internal", port: 3306, user: "n09-runtime",
    password: "not-a-real-secret", database: "n09_admin_preprod", ssl: true,
  });
  assert.throws(() => mariaDbConfigFromEnvironment({ ...databaseEnvironment, N09_DB_PASSWORD: "" }), /PASSWORD/);
  assert.throws(() => mariaDbConfigFromEnvironment({ ...databaseEnvironment, N09_DB_SSL: "false" }), /must be true/);
});

test("prépare l'émission puis l'opposabilité des sessions Tâches uniquement en préproduction", () => {
  assert.deepEqual(tasksApplicationSessionConfigFromEnvironment({}), {
    mode: "disabled", applicationId: "n09-suivi-taches",
    idleTtlMs: 3_600_000, absoluteTtlMs: 14_400_000, touchIntervalMs: 300_000,
  });
  assert.deepEqual(tasksApplicationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "preprod",
    N09_TASKS_SESSION_MODE: "issue",
  }).mode, "issue");
  assert.deepEqual(tasksApplicationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "preprod",
    N09_TASKS_SESSION_MODE: "enforce",
  }).mode, "enforce");
  assert.throws(() => tasksApplicationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "production", N09_TASKS_SESSION_MODE: "enforce",
  }), /restricted to preprod/);
  assert.throws(() => tasksApplicationSessionConfigFromEnvironment({
    N09_TASKS_SESSION_MODE: "observe",
  }), /disabled, issue or enforce/);
});

test("maintient le transport sur la boucle locale avant OIDC", () => {
  assert.deepEqual(httpConfigFromEnvironment({}), { host: "127.0.0.1", port: 3000 });
  assert.deepEqual(httpConfigFromEnvironment({ N09_HTTP_HOST: "::1", N09_HTTP_PORT: "3100" }), {
    host: "::1", port: 3100,
  });
  assert.deepEqual(httpConfigFromEnvironment({
    N09_HTTP_HOST: "0.0.0.0", N09_TRUSTED_REVERSE_PROXY: "true", PORT: "3200",
  }), { host: "0.0.0.0", port: 3200 });
  assert.throws(() => httpConfigFromEnvironment({ N09_HTTP_HOST: "0.0.0.0" }), /trusted reverse proxy/);
  assert.throws(() => httpConfigFromEnvironment({ N09_HTTP_PORT: "70000" }), /port/);
});

test("prépare l'observation puis l'opposabilité des sessions Administration en préproduction", () => {
  assert.deepEqual(administrationSessionConfigFromEnvironment({}), {
    mode: "disabled", applicationId: "n09-administration",
    idleTtlMs: 1_800_000, absoluteTtlMs: 28_800_000, touchIntervalMs: 300_000,
  });
  assert.deepEqual(administrationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "preprod", N09_ADMIN_SESSION_MODE: "observe",
    N09_ADMIN_SESSION_IDLE_TTL_MS: "600000",
    N09_ADMIN_SESSION_ABSOLUTE_TTL_MS: "3600000",
    N09_ADMIN_SESSION_TOUCH_INTERVAL_MS: "120000",
  }), {
    mode: "observe", applicationId: "n09-administration",
    idleTtlMs: 600_000, absoluteTtlMs: 3_600_000, touchIntervalMs: 120_000,
  });
  assert.equal(administrationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "preprod", N09_ADMIN_SESSION_MODE: "enforce",
  }).mode, "enforce");
  assert.throws(() => administrationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "production", N09_ADMIN_SESSION_MODE: "enforce",
  }), /restricted to preprod/);
  assert.throws(() => administrationSessionConfigFromEnvironment({
    N09_ADMIN_SESSION_MODE: "issue",
  }), /disabled, observe or enforce/);
  assert.throws(() => administrationSessionConfigFromEnvironment({
    N09_ADMIN_SESSION_IDLE_TTL_MS: "300000", N09_ADMIN_SESSION_TOUCH_INTERVAL_MS: "300000",
  }), /lifetime/);
  assert.equal(administrationSessionConfigFromEnvironment({
    N09_ENVIRONMENT: "preprod", N09_SESSION_SHADOW_MODE: "observe",
  }).mode, "observe");
});
