import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createHttpHandler } from "./http.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const currentSessionId = "00000000-0000-4000-8000-000000000051";
const targetSessionId = "00000000-0000-4000-8000-000000000052";
const csrf = "personal-sessions-csrf";
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

function sessionCookie({ centralSession = true } = {}) {
  return `${OIDC_SESSION_COOKIE}=${seal({
    sessionVersion: 2,
    issuer: "https://login.infomaniak.com",
    subject: "provider-subject",
    identityId,
    displayName: "Fred",
    status: "authenticated",
    csrf,
    centralSession: centralSession ? { sessionId: currentSessionId, secret: "S".repeat(43) } : null,
    expiresAt: Date.now() + 60_000,
  }, oidcConfig.sessionSecret, "oidc-session")}`;
}

const sessions = [
  {
    sessionId: currentSessionId, version: 2, applicationId: "n09-administration",
    applicationName: "N09 – Administration", contextLabel: "Navigateur Administration",
    issuedAt: "2026-08-13T10:00:00.000Z", lastSeenAt: "2026-08-13T11:55:00.000Z",
    idleExpiresAt: "2026-08-13T12:25:00.000Z", absoluteExpiresAt: "2026-08-13T18:00:00.000Z",
    state: "active", current: true,
  },
  {
    sessionId: targetSessionId, version: 4, applicationId: "n09-suivi-taches",
    applicationName: "N09 – Suivi des tâches", contextLabel: "Navigateur Tâches",
    issuedAt: "2026-08-13T09:00:00.000Z", lastSeenAt: "2026-08-13T11:30:00.000Z",
    idleExpiresAt: "2026-08-13T12:30:00.000Z", absoluteExpiresAt: "2026-08-13T13:00:00.000Z",
    state: "active", current: false,
  },
];

async function withServer(personalSessionManagement, operation) {
  const repository = {
    getIdentity: async () => ({ identityId, displayName: "Fred TRAVERS", email: "f.travers@nsktech.fr", status: "active" }),
    listApplications: async () => [{ applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches", status: "active" }],
    listAllAssignments: async () => [{
      assignmentId: "assignment-1", subjectId: identityId, applicationId: "n09-suivi-taches",
      roleId: "administrator", scopeType: "global", scopeId: null, status: "active",
    }],
  };
  const server = createServer(createHttpHandler({ repository, oidcConfig, personalSessionManagement }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await operation(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

test("présente le compte central sans permettre de modifier ses propres droits", async () => {
  await withServer({ listOwn: async () => sessions }, async (origin) => {
    const returnTo = "https://prod-taches.nsktech.fr/?theme=gray";
    const response = await fetch(`${origin}/account?return_to=${encodeURIComponent(returnTo)}&theme=gray`, {
      headers: { cookie: sessionCookie() },
    });
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Mon compte NSK Tech 09/);
    assert.match(html, /Fred TRAVERS/);
    assert.match(html, /f\.travers@nsktech\.fr/);
    assert.match(html, /N09 – Suivi des tâches/);
    assert.match(html, /Administrateur/);
    assert.match(html, /lecture seule/);
    assert.match(html, /Retour à l’application/);
    assert.doesNotMatch(html, /Accorder cet accès|action="\/admin\/access-decisions\/grant"/);
  });
});

test("présente le profil et les droits lorsque la gestion des sessions n’est pas activée", async () => {
  await withServer({
    listOwn: async () => assert.fail("l’inventaire de sessions ne doit pas être appelé"),
  }, async (origin) => {
    const returnTo = "https://prod-taches.nsktech.fr/?theme=gray";
    const response = await fetch(`${origin}/account?return_to=${encodeURIComponent(returnTo)}&theme=gray`, {
      headers: { cookie: sessionCookie({ centralSession: false }) },
    });
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Mon compte NSK Tech 09/);
    assert.match(html, /Fred TRAVERS/);
    assert.match(html, /N09 – Suivi des tâches/);
    assert.match(html, /Fonction temporairement indisponible/);
    assert.doesNotMatch(html, /Compte momentanément indisponible/);
    assert.doesNotMatch(html, /Gérer mes sessions/);
  });
});

test("présente les sessions sans identifiant technique et marque la courante", async () => {
  const calls = [];
  await withServer({
    listOwn: async (input) => { calls.push(input); return sessions; },
  }, async (origin) => {
    const response = await fetch(`${origin}/account/sessions`, { headers: { cookie: sessionCookie() } });
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Mes sessions/);
    assert.match(html, /Session actuelle/);
    assert.match(html, /N09 – Suivi des tâches/);
    assert.match(html, /Fermer toutes les autres sessions \(1\)/);
    assert.doesNotMatch(html, new RegExp(currentSessionId));
    assert.doesNotMatch(html, new RegExp(targetSessionId));
    assert.doesNotMatch(html, /secretHash|SSSSSS/i);
  });
  assert.deepEqual(calls, [{ identityId, currentSessionId }]);
});

test("révoque la cible issue du jeton chiffré avec CSRF", async () => {
  let revoked;
  await withServer({
    listOwn: async () => sessions,
    revokeOne: async (input) => { revoked = input; return { revoked: 1 }; },
  }, async (origin) => {
    const page = await fetch(`${origin}/account/sessions`, { headers: { cookie: sessionCookie() } });
    const html = await page.text();
    const target = html.match(/name="target" value="([^"]+)"/)?.[1];
    assert.ok(target);
    const response = await fetch(`${origin}/account/sessions/revoke`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, target }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"),
      "/account/sessions?return_to=https%3A%2F%2Fnsktech.fr%2F%23applications&theme=system");
  });
  assert.deepEqual(revoked, {
    identityId, currentSessionId, targetSessionId, expectedVersion: 4,
  });
});

test("conserve le retour vers Énergie dans le compte et ses actions", async () => {
  await withServer({
    listOwn: async () => sessions,
  }, async (origin) => {
    const returnTo = "https://energie.nsktech.fr/?theme=gray#historique";
    const page = await fetch(`${origin}/account/sessions?return_to=${encodeURIComponent(returnTo)}&theme=gray`, {
      headers: { cookie: sessionCookie() },
    });
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Retour à l’application/);
    assert.match(html, /href="https:\/\/energie\.nsktech\.fr\/\?theme=gray#historique"/);
    assert.match(html, new RegExp(`/account/sessions/revoke\\?return_to=${encodeURIComponent(returnTo)}`));
  });
});

test("refuse CSRF, jeton altéré et jeton d’une autre identité sans mutation", async () => {
  let calls = 0;
  const management = { revokeOne: async () => { calls += 1; } };
  await withServer(management, async (origin) => {
    const foreignTarget = seal({
      identityId: "70a40cd7-f2a4-4393-8021-9f806b42b41b",
      targetSessionId, expectedVersion: 4, expiresAt: Date.now() + 60_000,
    }, oidcConfig.sessionSecret, "personal-session-action");
    for (const [csrfValue, target, expectedStatus] of [
      ["incorrect", foreignTarget, 403],
      [csrf, `${foreignTarget}altered`, 400],
      [csrf, foreignTarget, 400],
    ]) {
      const response = await fetch(`${origin}/account/sessions/revoke`, {
        method: "POST",
        headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: csrfValue, target }),
      });
      assert.equal(response.status, expectedStatus);
    }
  });
  assert.equal(calls, 0);
});

test("ferme toutes les autres sessions sans cible fournie par le navigateur", async () => {
  let request;
  await withServer({
    revokeAllOthers: async (input) => { request = input; return { revoked: 2 }; },
  }, async (origin) => {
    const response = await fetch(`${origin}/account/sessions/revoke-others`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf }),
    });
    assert.equal(response.status, 303);
  });
  assert.deepEqual(request, { identityId, currentSessionId });
});
