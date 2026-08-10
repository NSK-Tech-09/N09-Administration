import assert from "node:assert/strict";
import test from "node:test";
import { httpConfigFromEnvironment, mariaDbConfigFromEnvironment } from "./runtime-config.mjs";

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

test("maintient le transport sur la boucle locale avant OIDC", () => {
  assert.deepEqual(httpConfigFromEnvironment({}), { host: "127.0.0.1", port: 3000 });
  assert.deepEqual(httpConfigFromEnvironment({ N09_HTTP_HOST: "::1", N09_HTTP_PORT: "3100" }), {
    host: "::1", port: 3100,
  });
  assert.throws(() => httpConfigFromEnvironment({ N09_HTTP_HOST: "0.0.0.0" }), /loopback/);
  assert.throws(() => httpConfigFromEnvironment({ N09_HTTP_PORT: "70000" }), /port/);
});
