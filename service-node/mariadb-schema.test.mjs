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

test("la boite de notification conserve la charge et borne les transitions", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS notification_events/);
  assert.match(schema, /PRIMARY KEY \(source_application_id, source_event_id\)/);
  assert.match(schema, /status IN \('pending', 'processing', 'retry', 'processed', 'quarantined'\)/);
  assert.match(schema, /notification_events_no_delete/);
  assert.match(schema, /notification_events_payload_immutable/);
  assert.match(schema, /notification event payload is immutable/);
  const table = schema.match(/CREATE TABLE IF NOT EXISTS notification_events[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(table, /email|password|credential|access_token|refresh_token/i);
});

test("le centre interne sépare matérialisation et canaux externes bloqués", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS notification_resolutions/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS notifications/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS notification_external_deliveries/);
  assert.match(schema, /UNIQUE KEY notifications_event_recipient/);
  assert.match(schema, /notifications_recipient_unread/);
  assert.match(schema, /status IN \('blocked', 'pending', 'processing', 'retry', 'delivered', 'quarantined'\)/);
  assert.match(schema, /status = 'blocked' AND blocked_reason IS NOT NULL/);
  assert.match(schema, /notification_external_delivery_claim/);
  assert.match(schema, /notification_external_delivery_completion/);
  assert.match(schema, /notification_external_delivery_error/);
  assert.match(schema, /notification_resolutions_no_update/);
  assert.match(schema, /notification_resolutions_no_delete/);
  assert.match(schema, /notifications_no_delete/);
  assert.match(schema, /notifications_payload_immutable/);
  const notificationTable = schema.match(/CREATE TABLE IF NOT EXISTS notifications[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(notificationTable, /email|password|secret|token/i);
});
