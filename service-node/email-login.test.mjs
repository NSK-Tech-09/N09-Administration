import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  consumeEmailLogin, createEmailLoginDelivery, emailLoginConfigFromEnvironment,
  hashEmailLoginToken, requestEmailLogin,
} from "./email-login.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "e13cbf95-e8bc-402c-bbb9-5f8d8aa25b6e",
  email: "f.travers@nsktech.fr", displayName: "Fred TRAVERS", status: "active",
};

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "email-login-tests",
    correlationId: randomUUID(), subjectId: identity.identityId,
  }));
  return repository;
}

test("garde le canal désactivé par défaut et valide entièrement son activation", () => {
  assert.deepEqual(emailLoginConfigFromEnvironment({}), { enabled: false });
  assert.throws(() => emailLoginConfigFromEnvironment({ N09_EMAIL_LOGIN_ENABLED: "true" }), /missing email login setting/);
  const config = emailLoginConfigFromEnvironment({
    N09_EMAIL_LOGIN_ENABLED: "true", N09_EMAIL_LOGIN_DELIVERY_PROVIDER: "brevo",
    N09_EMAIL_LOGIN_SENDER_EMAIL: "ne-pas-repondre@nsktech.fr",
    N09_EMAIL_LOGIN_SENDER_NAME: "NSK Tech 09",
    N09_EMAIL_LOGIN_BREVO_API_KEY: "x".repeat(32),
    N09_PUBLIC_ORIGIN: "https://prod-admin.nsktech.fr",
  });
  assert.equal(config.enabled, true);
  assert.equal(config.publicOrigin, "https://prod-admin.nsktech.fr");
});

test("émet un lien pour une identité active sans conserver le secret brut", async () => {
  const repository = seededRepository();
  const deliveries = [];
  const token = "A".repeat(43);
  const result = await requestEmailLogin({
    repository, email: " F.TRAVERS@NSKTECH.FR ", returnTo: "/account/sessions?theme=dark",
    delivery: { enabled: true, send: async (message) => deliveries.push(message) },
    publicOrigin: "https://prod-admin.nsktech.fr", tokenFactory: () => token,
    now: new Date("2026-08-15T08:00:00.000Z"),
  });
  assert.deepEqual(result, { accepted: true, delivered: true });
  assert.equal(deliveries.length, 1);
  assert.match(deliveries[0].loginUrl, /\/auth\/email\/confirm\?token=/);
  const stored = repository.getEmailLoginToken(hashEmailLoginToken(token));
  assert.equal(stored.identityId, identity.identityId);
  assert.equal(stored.expiresAt, "2026-08-15T08:10:00.000Z");
  assert.doesNotMatch(JSON.stringify(stored), new RegExp(token));
  assert.doesNotMatch(JSON.stringify(repository.auditSnapshot()), new RegExp(token));
});

test("répond de façon neutre pour une adresse inconnue sans créer de compte", async () => {
  const repository = seededRepository();
  let deliveries = 0;
  const result = await requestEmailLogin({
    repository, email: "inconnue@example.test", returnTo: "/",
    delivery: { enabled: true, send: async () => { deliveries += 1; } },
    publicOrigin: "https://prod-admin.nsktech.fr",
  });
  assert.deepEqual(result, { accepted: true, delivered: false });
  assert.equal(deliveries, 0);
  assert.equal(repository.listIdentities().length, 1);
});

test("consomme le lien exactement une fois et refuse son rejeu", async () => {
  const repository = seededRepository();
  const token = "B".repeat(43);
  await requestEmailLogin({
    repository, email: identity.email, returnTo: "/",
    delivery: { enabled: true, send: async () => {} },
    publicOrigin: "https://prod-admin.nsktech.fr", tokenFactory: () => token,
    now: new Date("2026-08-15T08:00:00.000Z"),
  });
  const result = await consumeEmailLogin({ repository, token, now: new Date("2026-08-15T08:05:00.000Z") });
  assert.equal(result.identity.identityId, identity.identityId);
  assert.equal(result.returnTo, "/");
  await assert.rejects(
    consumeEmailLogin({ repository, token, now: new Date("2026-08-15T08:06:00.000Z") }),
    /invalid_or_consumed_email_login/,
  );
});

test("refuse un lien arrivé à expiration sans le consommer", async () => {
  const repository = seededRepository();
  const token = "D".repeat(43);
  await requestEmailLogin({
    repository, email: identity.email, returnTo: "/",
    delivery: { enabled: true, send: async () => {} },
    publicOrigin: "https://prod-admin.nsktech.fr", tokenFactory: () => token,
    now: new Date("2026-08-15T08:00:00.000Z"),
  });
  await assert.rejects(
    consumeEmailLogin({ repository, token, now: new Date("2026-08-15T08:10:00.000Z") }),
    /invalid_or_consumed_email_login/,
  );
  assert.equal(repository.getEmailLoginToken(hashEmailLoginToken(token)).status, "issued");
});

test("invalide et audite un lien dont l’envoi échoue", async () => {
  const repository = seededRepository();
  const token = "C".repeat(43);
  await assert.rejects(requestEmailLogin({
    repository, email: identity.email, returnTo: "/",
    delivery: { enabled: true, send: async () => { throw new Error("provider unavailable"); } },
    publicOrigin: "https://prod-admin.nsktech.fr", tokenFactory: () => token,
    now: new Date("2026-08-15T08:00:00.000Z"),
  }), (error) => error.code === "email_login_delivery_failed" && error.status === 503);
  const stored = repository.getEmailLoginToken(hashEmailLoginToken(token));
  assert.equal(stored.status, "delivery_failed");
  assert.equal(stored.consumedAt, null);
  assert.ok(stored.invalidatedAt);
  await assert.rejects(consumeEmailLogin({ repository, token }), /invalid_or_consumed_email_login/);
});

test("l’adaptateur Brevo utilise uniquement l’API transactionnelle protégée", async () => {
  let captured;
  const delivery = createEmailLoginDelivery({
    enabled: true, apiKey: "protected-api-key", senderEmail: "ne-pas-repondre@nsktech.fr",
    senderName: "NSK Tech 09",
  }, { fetchImpl: async (url, options) => { captured = { url, options }; return { ok: true }; } });
  await delivery.send({
    to: identity.email, displayName: identity.displayName,
    loginUrl: "https://prod-admin.nsktech.fr/auth/email/confirm?token=opaque",
  });
  assert.equal(captured.url, "https://api.brevo.com/v3/smtp/email");
  assert.equal(captured.options.headers["api-key"], "protected-api-key");
  assert.doesNotMatch(captured.options.body, /protected-api-key/);
  assert.match(captured.options.body, /n09-email-login/);
});
