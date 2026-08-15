import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schema = await readFile(new URL("./mariadb/schema.sql", import.meta.url), "utf8");
const sessionMigration = await readFile(new URL("./mariadb/migrations/20260813-application-sessions.sql", import.meta.url), "utf8");
const sessionChecks = await readFile(new URL("./mariadb/migrations/20260813-application-sessions-checks.sql", import.meta.url), "utf8");
const accessRequestMigration = await readFile(new URL("./mariadb/migrations/20260815-access-requests.sql", import.meta.url), "utf8");
const emailLoginMigration = await readFile(new URL("./mariadb/migrations/20260815-email-login.sql", import.meta.url), "utf8");

function normalizedSql(value) {
  return value.replaceAll(/--[^\n]*/g, "").replaceAll(/\s+/g, " ").trim();
}

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

test("le registre de sessions ne conserve jamais le secret brut", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS application_sessions/);
  assert.match(schema, /session_id CHAR\(36\) PRIMARY KEY/);
  assert.match(schema, /secret_hash CHAR\(64\) NOT NULL/);
  assert.match(schema, /idle_expires_at DATETIME\(6\) NOT NULL/);
  assert.match(schema, /absolute_expires_at DATETIME\(6\) NOT NULL/);
  assert.match(schema, /revoked_at DATETIME\(6\)/);
  assert.match(schema, /application_sessions_revocation CHECK/);
  const table = schema.match(/CREATE TABLE IF NOT EXISTS application_sessions[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(table, /session_secret|secret_value|raw_secret|cookie|access_token|refresh_token/i);
});

test("la migration de préproduction reproduit exactement le registre fusionné", () => {
  const canonicalTable = schema.match(/CREATE TABLE IF NOT EXISTS application_sessions[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  const migrationTable = sessionMigration.match(/CREATE TABLE IF NOT EXISTS application_sessions[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.equal(normalizedSql(migrationTable), normalizedSql(canonicalTable));
  assert.match(sessionChecks, /information_schema\.tables/);
  assert.match(sessionChecks, /information_schema\.columns/);
  assert.match(sessionChecks, /information_schema\.statistics/);
  assert.match(sessionChecks, /information_schema\.referential_constraints/);
  assert.match(sessionChecks, /SELECT COUNT\(\*\) AS application_session_count\s+FROM application_sessions/);
  assert.doesNotMatch(sessionChecks, /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b/i);
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

test("la connexion courriel ne conserve que l’empreinte et sa migration canonique", () => {
  const canonicalTable = schema.match(/CREATE TABLE IF NOT EXISTS email_login_tokens[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  const migrationTable = emailLoginMigration.match(/CREATE TABLE IF NOT EXISTS email_login_tokens[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.equal(normalizedSql(migrationTable), normalizedSql(canonicalTable));
  assert.match(canonicalTable, /token_hash CHAR\(64\) NOT NULL UNIQUE/);
  assert.match(canonicalTable, /status IN \('issued', 'consumed', 'delivery_failed'\)/);
  assert.match(canonicalTable, /expires_at > requested_at/);
  assert.doesNotMatch(canonicalTable, /raw_token|token_value|email VARCHAR|password|credential/i);
});

test("les demandes d’accès séparent les coordonnées, les lignes et les affectations gouvernées", () => {
  for (const tableName of ["access_requests", "access_request_lines"]) {
    const expression = new RegExp(`CREATE TABLE IF NOT EXISTS ${tableName}[\\s\\S]*?ENGINE=InnoDB;`);
    assert.equal(
      normalizedSql(accessRequestMigration.match(expression)?.[0] ?? ""),
      normalizedSql(schema.match(expression)?.[0] ?? ""),
    );
  }
  assert.match(schema, /access_request_lines_assignment_fk FOREIGN KEY \(assignment_id\) REFERENCES access_assignments/);
  assert.match(schema, /access_request_lines_decision CHECK/);
  assert.match(schema, /UNIQUE KEY access_request_lines_application \(request_id, application_id\)/);
  const requestTable = schema.match(/CREATE TABLE IF NOT EXISTS access_requests[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(requestTable, /password|secret|token|credential/i);
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
  assert.match(schema, /UNIQUE KEY notification_external_delivery_channel \(notification_id, channel\)/);
  assert.match(schema, /CONSTRAINT notification_external_delivery_channel_value CHECK/);
  assert.doesNotMatch(schema, /CONSTRAINT notification_external_delivery_channel CHECK/);
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

test("l'état du consommateur reste singleton, borné et sans charge métier", () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS notification_processing_state/);
  assert.match(schema, /consumer_id = 'internal-materializer-v1'/);
  assert.match(schema, /last_status IN \('succeeded', 'failed'\)/);
  assert.match(schema, /last_finished_at >= last_started_at/);
  const table = schema.match(/CREATE TABLE IF NOT EXISTS notification_processing_state[\s\S]*?ENGINE=InnoDB;/)?.[0] ?? "";
  assert.doesNotMatch(table, /payload|title|message|email|address|secret|token/i);
});
