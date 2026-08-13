import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createHttpHandler } from "./http.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const csrf = "notification-csrf";
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

function sessionCookie() {
  const session = {
    sessionVersion: 2,
    issuer: "https://login.infomaniak.com", subject: "provider-subject", identityId,
    displayName: "Fred", status: "authenticated", csrf, expiresAt: Date.now() + 60_000,
  };
  return `${OIDC_SESSION_COOKIE}=${seal(session, oidcConfig.sessionSecret, "oidc-session")}`;
}

async function withServer(repository, operation) {
  const server = createServer(createHttpHandler({ repository, oidcConfig }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await operation(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function notification() {
  return {
    notificationId: "a".repeat(64), sourceApplicationId: "n09-suivi-taches",
    sourceApplicationName: "N09 – Suivi des tâches", category: "task_activity",
    importance: "information", title: "Tâche archivée",
    message: "Une tâche a été archivée dans N09 – Suivi des tâches.",
    contextApplicationId: "n09-suivi-taches", contextResourceType: "task", contextResourceId: "task_1",
    occurredAt: "2026-08-12T10:00:00.000Z", createdAt: "2026-08-12T10:02:00.000Z",
    readAt: null, archivedAt: null,
  };
}

test("présente le centre personnel avec compteur, source et contexte", async () => {
  const repository = {
    listNotifications: async (receivedIdentity) => {
      assert.equal(receivedIdentity, identityId);
      return [notification()];
    },
    countUnreadNotifications: async () => 1,
  };
  await withServer(repository, async (origin) => {
    const response = await fetch(`${origin}/notifications`, { headers: { cookie: sessionCookie() } });
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Centre de notifications/);
    assert.match(html, /Tâche archivée/);
    assert.match(html, /Non lue/);
    assert.match(html, /task_1/);
    assert.doesNotMatch(html, /Supprimer/);
  });
});

test("marque seulement la notification de l'identité de session", async () => {
  let command;
  const repository = {
    markNotificationRead: async (value) => { command = value; return { changed: true }; },
  };
  await withServer(repository, async (origin) => {
    const response = await fetch(`${origin}/notifications/${"a".repeat(64)}/read`, {
      method: "POST", redirect: "manual", headers: {
        cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({ csrf }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/notifications");
  });
  assert.equal(command.identityId, identityId);
  assert.equal(command.notificationId, "a".repeat(64));
  assert.ok(command.readAt instanceof Date);
});

test("refuse une écriture sans session ou avec un jeton CSRF erroné", async () => {
  let called = false;
  const repository = { markAllNotificationsRead: async () => { called = true; } };
  await withServer(repository, async (origin) => {
    const anonymous = await fetch(`${origin}/notifications/read-all`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "csrf=x",
    });
    assert.equal(anonymous.status, 401);
    const invalidCsrf = await fetch(`${origin}/notifications/read-all`, {
      method: "POST", headers: {
        cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: "csrf=incorrect",
    });
    assert.equal(invalidCsrf.status, 403);
  });
  assert.equal(called, false);
});
