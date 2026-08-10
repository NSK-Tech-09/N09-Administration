import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schema = await readFile(new URL("./mariadb/schema.sql", import.meta.url), "utf8");

test("le registre applicatif porte retours, politique d’entrée et codes à usage unique", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS application_redirect_uris/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS application_login_policies/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS application_authorization_codes/);
  assert.match(schema, /code_hash CHAR\(64\) PRIMARY KEY/);
  assert.match(schema, /code_challenge CHAR\(43\) NOT NULL/);
  assert.match(schema, /consumed_at DATETIME\(6\)/);
  assert.doesNotMatch(schema, /\bcode\s+VARCHAR/i);
  assert.doesNotMatch(schema, /access_token|refresh_token|id_token/i);
});

test("le catalogue applicatif conserve chaque version sans secret", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS application_access_catalog_versions/);
  assert.match(schema, /PRIMARY KEY \(application_id, catalog_version\)/);
  assert.match(schema, /catalog_hash CHAR\(64\) NOT NULL/);
  assert.match(schema, /roles_json JSON NOT NULL/);
  assert.match(schema, /provisioning_json JSON NOT NULL/);
  const catalogTable = schema.match(/CREATE TABLE IF NOT EXISTS application_access_catalog_versions[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(catalogTable, /secret|certificate|token/i);
});
