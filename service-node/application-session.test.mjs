import assert from "node:assert/strict";
import test from "node:test";
import {
  assessApplicationSession,
  createApplicationSession,
  revokeApplicationSession,
  touchApplicationSession,
} from "./application-session.mjs";

const now = new Date("2026-08-13T03:00:00.000Z");
const defaults = {
  identityId: "00000000-0000-4000-8000-000000000001",
  applicationId: "n09-suivi-taches",
  idleTtlMs: 60 * 60_000,
  absoluteTtlMs: 4 * 60 * 60_000,
  authenticatedAt: new Date("2026-08-13T02:59:00.000Z"),
  now,
  randomUuidImpl: () => "00000000-0000-4000-8000-000000000042",
  randomBytesImpl: () => Buffer.alloc(32, 7),
};

function activeSession(overrides = {}) {
  return createApplicationSession({ ...defaults, ...overrides });
}

test("crée un secret imprévisible séparé d’un registre sans secret brut", () => {
  const { credential, record } = activeSession();
  assert.equal(credential.sessionId, record.sessionId);
  assert.equal(credential.secret.length, 43);
  assert.match(record.secretHash, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(record).includes(credential.secret), false);
  assert.equal(record.idleExpiresAt, "2026-08-13T04:00:00.000Z");
  assert.equal(record.absoluteExpiresAt, "2026-08-13T07:00:00.000Z");
  assert.equal(record.version, 1);
});

test("refuse les durées incohérentes ou excessives", () => {
  assert.throws(() => activeSession({ idleTtlMs: 60_000 }), /invalid_session_lifetime/);
  assert.throws(() => activeSession({ idleTtlMs: 5 * 60 * 60_000 }), /invalid_session_lifetime/);
  assert.throws(() => activeSession({ absoluteTtlMs: 25 * 60 * 60_000 }), /invalid_session_lifetime/);
});

test("accepte seulement le secret, l’identité et l’application liés", () => {
  const { credential, record } = activeSession();
  const request = { ...credential, identityId: record.identityId, applicationId: record.applicationId, now };
  assert.deepEqual(assessApplicationSession(record, request), { allowed: true, reasonCode: "session_active" });
  assert.equal(assessApplicationSession(record, { ...request, secret: "A".repeat(43) }).reasonCode, "session_secret_invalid");
  assert.equal(assessApplicationSession(record, { ...request, identityId: "identity-2" }).reasonCode, "session_context_mismatch");
  assert.equal(assessApplicationSession(record, { ...request, applicationId: "other-app" }).reasonCode, "session_context_mismatch");
});

test("distingue expiration d’inactivité, expiration absolue et révocation", () => {
  const { credential, record } = activeSession();
  const request = { ...credential, identityId: record.identityId, applicationId: record.applicationId };
  assert.equal(assessApplicationSession(record, { ...request, now: record.idleExpiresAt }).reasonCode, "session_idle_expired");

  const absoluteFirst = { ...record, idleExpiresAt: record.absoluteExpiresAt };
  assert.equal(assessApplicationSession(absoluteFirst, { ...request, now: record.absoluteExpiresAt }).reasonCode, "session_absolute_expired");

  const revoked = revokeApplicationSession(record, { reason: "Déconnexion demandée", now: new Date("2026-08-13T03:10:00Z") });
  assert.equal(assessApplicationSession(revoked, { ...request, now: new Date("2026-08-13T03:11:00Z") }).reasonCode, "session_revoked");
});

test("prolonge l’inactivité sans dépasser l’échéance absolue", () => {
  const { record } = activeSession({ idleTtlMs: 3 * 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000 });
  const touched = touchApplicationSession(record, { now: new Date("2026-08-13T05:30:00.000Z") });
  assert.equal(touched.lastSeenAt, "2026-08-13T05:30:00.000Z");
  assert.equal(touched.idleExpiresAt, record.absoluteExpiresAt);
  assert.equal(touched.version, 2);
});

test("révoque une seule fois avec une cause bornée", () => {
  const { record } = activeSession();
  const revoked = revokeApplicationSession(record, {
    revokedByIdentityId: record.identityId,
    reason: "Fermeture de la session distante",
    now: new Date("2026-08-13T03:15:00.000Z"),
  });
  assert.equal(revoked.revokedAt, "2026-08-13T03:15:00.000Z");
  assert.equal(revoked.version, 2);
  assert.equal(revokeApplicationSession(revoked, { reason: "Nouvelle demande" }), revoked);
  assert.throws(() => revokeApplicationSession(record, { reason: "" }), /invalid_revocation_reason/);
});
