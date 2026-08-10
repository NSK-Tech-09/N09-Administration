import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";
import { prepareApplicationAccessCatalog } from "./application-access-catalog.mjs";

const identity = { identityId: "identity-1", email: "COLLEGUE@example.test", displayName: "Collègue", status: "active" };
const audit = (changes = {}) => createAuditEvent({
  action: "identity.created", result: "success", source: "tests", correlationId: "correlation-1",
  subjectId: "identity-1", eventId: "event-1", occurredAt: new Date("2026-08-10T06:00:00Z"), ...changes,
});

function fakePool({ failAudit = false } = {}) {
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"),
    commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"),
    release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT identity_id")) return [[]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      if (failAudit && sql.includes("INSERT INTO audit_events")) throw new Error("audit unavailable");
      return [{ affectedRows: 1 }];
    },
  };
  return { calls, getConnection: async () => connection };
}

test("refuse une configuration MariaDB incomplète", async () => {
  await assert.rejects(createMariaDbPool({ host: "db", user: "n09", password: "secret" }), /database/);
});

test("valide écriture métier et audit dans une seule transaction", async () => {
  const pool = fakePool();
  await new MariaDbRepository(pool).saveIdentity(identity, audit());
  assert.equal(pool.calls[0], "begin");
  assert.equal(pool.calls.at(-2), "commit");
  assert.equal(pool.calls.at(-1), "release");
  assert.equal(pool.calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
});

test("annule l’écriture métier si l’audit échoue", async () => {
  const pool = fakePool({ failAudit: true });
  await assert.rejects(new MariaDbRepository(pool).saveIdentity(identity, audit()), /audit unavailable/);
  assert.equal(pool.calls.at(-2), "rollback");
  assert.equal(pool.calls.at(-1), "release");
  assert.equal(pool.calls.includes("commit"), false);
});

test("refuse un contexte d’audit incohérent avant d’ouvrir une transaction", async () => {
  const pool = fakePool();
  await assert.rejects(new MariaDbRepository(pool).saveIdentity(identity, audit({ subjectId: "identity-2" })), /must match/);
  assert.equal(pool.calls.length, 0);
});

test("persiste la demande de rattachement et son audit dans la même transaction", async () => {
  const pool = fakePool();
  const requestedAt = new Date("2026-08-10T09:00:00Z");
  const request = createLinkRequest({
    issuer: "https://login.infomaniak.com", subject: "external-42",
    providerKey: "infomaniak", now: requestedAt,
  });
  const event = createAuditEvent({
    action: "external_identity.link_requested", result: "pending",
    source: "tests", correlationId: "correlation-link", occurredAt: requestedAt,
  });
  await new MariaDbRepository(pool).saveLinkRequest(request, event);
  assert.equal(pool.calls[0], "begin");
  assert.equal(pool.calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO external_identity_link_requests")), true);
  assert.equal(pool.calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(pool.calls.at(-2), "commit");
});

test("persiste une version de catalogue et son audit dans la même transaction", async () => {
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"),
    commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"),
    release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM applications") && sql.includes("FOR UPDATE")) return [[{ application_id: "tasks" }]];
      if (sql.includes("FROM application_access_catalog_versions")) return [[]];
      if (sql.includes("FROM access_assignments")) return [[]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  const pool = { getConnection: async () => connection };
  const catalog = prepareApplicationAccessCatalog({
    application_id: "tasks", catalog_version: 1,
    permissions: [{ permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tâches.", status: "active" }],
    scope_types: [{ scope_type_id: "global", display_name: "Global", description: "Toute l’application.", status: "active" }],
    roles: [{ role_id: "tasks-reader", display_name: "Lecteur", description: "Lecture globale.", status: "active", permissions: ["tasks:read"], scope_types: ["global"] }],
    provisioning: { mode: "central_identity_only", identity_key: "identity_id", readiness: "immediate", automatic_profile_creation: false, email_matching: "forbidden", requirements: [] },
  });
  const event = createAuditEvent({
    action: "application.access_catalog_published", result: "success", source: "tests",
    correlationId: "catalog-correlation", applicationId: "tasks",
  });
  const result = await new MariaDbRepository(pool).publishApplicationAccessCatalog(catalog, event);
  assert.equal(result.created, true);
  assert.equal(calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO application_access_catalog_versions")), true);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(calls.at(-2), "commit");
  assert.equal(calls.at(-1), "release");
});
