import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createHttpHandler } from "./http.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";
import { SESSION_REVOCATION_PERMISSION } from "./operator-session-management.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operatorId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const targetIdentityId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const currentSessionId = "00000000-0000-4000-8000-000000000051";
const targetSessionId = "00000000-0000-4000-8000-000000000052";
const csrf = "operator-sessions-csrf";
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "operator-session-http-tests",
    correlationId: crypto.randomUUID(), justification: "Préparation contrôlée du test", ...changes,
  });
}

function repositoryWithPermission(permission = SESSION_REVOCATION_PERMISSION) {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId: operatorId, email: "operator@example.test", displayName: "Opérateur", status: "active",
  }, audit("identity.created", { subjectId: operatorId }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  repository.saveAssignment({
    assignmentId: "10000000-0000-4000-8000-000000000053",
    subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    roleId: "session-revocation-administrator", permissions: [permission],
    scopeType: null, scopeId: null, conditions: [], status: "active",
    validFrom: null, validUntil: null, reason: "Pouvoir séparé pour le test",
    decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

function sessionCookie(identityId = operatorId) {
  return `${OIDC_SESSION_COOKIE}=${seal({
    sessionVersion: 2, issuer: "https://login.infomaniak.com", subject: "provider-subject",
    identityId, displayName: "Opérateur", status: "authenticated", csrf,
    centralSession: { sessionId: currentSessionId, secret: "S".repeat(43) },
    expiresAt: Date.now() + 60_000,
  }, oidcConfig.sessionSecret, "oidc-session")}`;
}

const sessions = [
  {
    sessionId: currentSessionId, version: 2, identityId: operatorId,
    identityName: "Opérateur", identityEmail: "operator@example.test", identityStatus: "active",
    applicationId: ADMIN_APPLICATION_ID, applicationName: "N09 – Administration",
    contextLabel: "Navigateur Administration", issuedAt: "2026-08-13T10:00:00.000Z",
    lastSeenAt: "2026-08-13T11:55:00.000Z", idleExpiresAt: "2026-08-13T12:25:00.000Z",
    absoluteExpiresAt: "2026-08-13T18:00:00.000Z", current: true,
  },
  {
    sessionId: targetSessionId, version: 4, identityId: targetIdentityId,
    identityName: "Personne cible", identityEmail: "target@example.test", identityStatus: "active",
    applicationId: "n09-suivi-taches", applicationName: "N09 – Suivi des tâches",
    contextLabel: "Navigateur Tâches", issuedAt: "2026-08-13T09:00:00.000Z",
    lastSeenAt: "2026-08-13T11:30:00.000Z", idleExpiresAt: "2026-08-13T12:30:00.000Z",
    absoluteExpiresAt: "2026-08-13T13:00:00.000Z", current: false,
  },
];

async function withServer({ repository = repositoryWithPermission(), operatorSessionManagement }, operation) {
  const server = createServer(createHttpHandler({ repository, oidcConfig, operatorSessionManagement }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await operation(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

test("affiche l’accès à la console seulement avec la permission dédiée", async () => {
  for (const [repository, visible] of [
    [repositoryWithPermission(), true],
    [repositoryWithPermission("administration:access:read"), false],
  ]) {
    await withServer({ repository }, async (origin) => {
      const response = await fetch(origin, { headers: { cookie: sessionCookie() } });
      const html = await response.text();
      assert.equal(response.status, 200);
      assert.equal(html.includes('href="/admin/sessions"'), visible);
    });
  }
});

test("présente la console sans identifiant technique ni secret", async () => {
  const calls = [];
  await withServer({
    operatorSessionManagement: {
      listActive: async (input) => { calls.push(input); return sessions; },
    },
  }, async (origin) => {
    const response = await fetch(`${origin}/admin/sessions`, { headers: { cookie: sessionCookie() } });
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Sessions actives de l’écosystème/);
    assert.match(html, /Personne cible/);
    assert.match(html, /permission dédiée/);
    assert.match(html, /session opérateur courante/);
    assert.doesNotMatch(html, new RegExp(currentSessionId));
    assert.doesNotMatch(html, new RegExp(targetSessionId));
    assert.doesNotMatch(html, /secretHash|SSSSSS/i);
  });
  assert.deepEqual(calls, [{ operatorIdentityId: operatorId, currentSessionId }]);
});

test("révoque uniquement la cible scellée avec CSRF et justification", async () => {
  let revoked;
  await withServer({
    operatorSessionManagement: {
      listActive: async () => sessions,
      revokeOne: async (input) => { revoked = input; return { revoked: 1 }; },
    },
  }, async (origin) => {
    const page = await fetch(`${origin}/admin/sessions`, { headers: { cookie: sessionCookie() } });
    const html = await page.text();
    const target = html.match(/name="target" value="([^"]+)"/)?.[1];
    assert.ok(target);
    const response = await fetch(`${origin}/admin/sessions/revoke`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        csrf, target, justification: "Session fermée après validation opérationnelle",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/sessions");
  });
  assert.deepEqual(revoked, {
    operatorIdentityId: operatorId, currentSessionId,
    targetIdentityId, targetSessionId, expectedVersion: 4,
    justification: "Session fermée après validation opérationnelle",
  });
});

test("refuse permission absente, CSRF, jeton altéré et opérateur différent sans mutation", async () => {
  await withServer({
    repository: repositoryWithPermission("administration:access:read"),
    operatorSessionManagement: { listActive: async () => sessions },
  }, async (origin) => {
    const response = await fetch(`${origin}/admin/sessions`, { headers: { cookie: sessionCookie() } });
    assert.equal(response.status, 403);
  });

  let calls = 0;
  await withServer({
    operatorSessionManagement: { revokeOne: async () => { calls += 1; } },
  }, async (origin) => {
    const foreignTarget = seal({
      operatorIdentityId: targetIdentityId, targetIdentityId, targetSessionId,
      expectedVersion: 4, expiresAt: Date.now() + 60_000,
    }, oidcConfig.sessionSecret, "operator-session-action");
    for (const [csrfValue, target, expectedStatus] of [
      ["incorrect", foreignTarget, 403],
      [csrf, `${foreignTarget}altered`, 400],
      [csrf, foreignTarget, 400],
    ]) {
      const response = await fetch(`${origin}/admin/sessions/revoke`, {
        method: "POST",
        headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          csrf: csrfValue, target, justification: "Session fermée après validation opérationnelle",
        }),
      });
      assert.equal(response.status, expectedStatus);
    }
  });
  assert.equal(calls, 0);
});
