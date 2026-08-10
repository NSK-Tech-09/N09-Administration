import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createMariaDbPool, MariaDbRepository } from "./mariadb.mjs";

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
