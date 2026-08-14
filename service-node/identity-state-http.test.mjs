import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createHttpHandler } from "./http.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  IDENTITY_DISABLEMENT_PERMISSION,
  IDENTITY_REACTIVATION_PERMISSION,
  IDENTITY_SUSPENSION_PERMISSION,
} from "./identity-state-management.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operatorId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const targetId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const currentSessionId = "00000000-0000-4000-8000-000000000071";
const csrf = "identity-state-csrf";
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "identity-state-http-tests",
    correlationId: crypto.randomUUID(), justification: "Préparation contrôlée du test", ...changes,
  });
}

function repositoryWithPermission(permission = IDENTITY_SUSPENSION_PERMISSION) {
  const repository = new TransactionalMemoryRepository();
  for (const [identityId, email, displayName] of [
    [operatorId, "operator@example.test", "Opérateur"],
    [targetId, "target@example.test", "Personne cible"],
  ]) {
    repository.saveIdentity({ identityId, email, displayName, status: "active" },
      audit("identity.created", { subjectId: identityId }));
  }
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  repository.saveAssignment({
    assignmentId: "10000000-0000-4000-8000-000000000055",
    subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    roleId: "identity-suspension-administrator", permissions: [permission],
    scopeType: null, scopeId: null, conditions: [], status: "active",
    validFrom: null, validUntil: null, reason: "Pouvoir séparé pour le test",
    decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

function sessionCookie() {
  return `${OIDC_SESSION_COOKIE}=${seal({
    sessionVersion: 2, issuer: "https://login.infomaniak.com", subject: "provider-subject",
    identityId: operatorId, displayName: "Opérateur", status: "authenticated", csrf,
    centralSession: { sessionId: currentSessionId, secret: "S".repeat(43) },
    expiresAt: Date.now() + 60_000,
  }, oidcConfig.sessionSecret, "oidc-session")}`;
}

const identities = [
  { identityId: operatorId, displayName: "Opérateur", email: "operator@example.test", status: "active", activeSessionCount: 1, current: true, canSuspend: false, canReactivate: false, canDisable: false },
  { identityId: targetId, displayName: "Personne cible", email: "target@example.test", status: "active", activeSessionCount: 2, current: false, canSuspend: true, canReactivate: false, canDisable: false },
];

async function withServer({ repository = repositoryWithPermission(), identityStateManagement }, operation) {
  const server = createServer(createHttpHandler({ repository, oidcConfig, identityStateManagement }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await operation(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

test("affiche la console seulement avec la permission dédiée", async () => {
  for (const [repository, visible] of [
    [repositoryWithPermission(), true],
    [repositoryWithPermission("administration:sessions:revoke"), false],
  ]) {
    await withServer({ repository }, async (origin) => {
      const response = await fetch(origin, { headers: { cookie: sessionCookie() } });
      assert.equal((await response.text()).includes('href="/admin/identities"'), visible);
    });
  }
});

test("présente les identités sans identifiant technique et protège l’auto-suspension", async () => {
  await withServer({ identityStateManagement: { listLifecycle: async () => identities } }, async (origin) => {
    const response = await fetch(`${origin}/admin/identities`, { headers: { cookie: sessionCookie() } });
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Cycle de vie des identités/);
    assert.match(html, /Personne cible/);
    assert.match(html, /Ta propre identité ne peut pas être suspendue/);
    assert.equal((html.match(/Suspendre l’identité et fermer ses sessions/g) ?? []).length, 1);
    assert.doesNotMatch(html, new RegExp(operatorId));
    assert.doesNotMatch(html, new RegExp(targetId));
  });
});

test("transmet uniquement la cible scellée avec CSRF et justification", async () => {
  let suspended;
  await withServer({
    identityStateManagement: {
      listLifecycle: async () => identities,
      suspend: async (input) => { suspended = input; return { revokedSessions: 2 }; },
    },
  }, async (origin) => {
    const page = await fetch(`${origin}/admin/identities`, { headers: { cookie: sessionCookie() } });
    const html = await page.text();
    const target = html.match(/name="target" value="([^"]+)"/)?.[1];
    assert.ok(target);
    const response = await fetch(`${origin}/admin/identities/suspend`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        csrf, target, justification: "Départ confirmé après contrôle humain de la situation",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/identities");
  });
  assert.deepEqual(suspended, {
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Départ confirmé après contrôle humain de la situation",
  });
});

test("refuse permission absente, CSRF et jeton altéré sans mutation", async () => {
  await withServer({
    repository: repositoryWithPermission("administration:sessions:revoke"),
    identityStateManagement: { listLifecycle: async () => identities },
  }, async (origin) => {
    assert.equal((await fetch(`${origin}/admin/identities`, { headers: { cookie: sessionCookie() } })).status, 403);
  });
  let calls = 0;
  await withServer({ identityStateManagement: { suspend: async () => { calls += 1; } } }, async (origin) => {
    const sealed = seal({
      operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
      expiresAt: Date.now() + 60_000,
    }, oidcConfig.sessionSecret, "identity-state-action");
    for (const [csrfValue, target, status] of [["incorrect", sealed, 403], [csrf, `${sealed}x`, 400]]) {
      const response = await fetch(`${origin}/admin/identities/suspend`, {
        method: "POST",
        headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          csrf: csrfValue, target, justification: "Départ confirmé après contrôle humain de la situation",
        }),
      });
      assert.equal(response.status, status);
    }
  });
  assert.equal(calls, 0);
});

test("présente et transmet une réactivation scellée sans restaurer de session", async () => {
  const repository = repositoryWithPermission(IDENTITY_REACTIVATION_PERMISSION);
  const suspended = [
    { ...identities[0], canSuspend: false },
    { ...identities[1], status: "suspended", activeSessionCount: 0, canSuspend: false, canReactivate: true },
  ];
  let reactivated;
  await withServer({
    repository,
    identityStateManagement: {
      listLifecycle: async () => suspended,
      reactivate: async (input) => { reactivated = input; return { restoredSessions: 0 }; },
    },
  }, async (origin) => {
    const page = await fetch(`${origin}/admin/identities`, { headers: { cookie: sessionCookie() } });
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Réactiver sans restaurer les anciennes sessions/);
    assert.match(html, /Non-résurrection/);
    const target = html.match(/name="target" value="([^"]+)"/)?.[1];
    const response = await fetch(`${origin}/admin/identities/reactivate`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        csrf, target, justification: "Retour validé après une nouvelle décision humaine explicite",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/identities");
  });
  assert.deepEqual(reactivated, {
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "suspended",
    justification: "Retour validé après une nouvelle décision humaine explicite",
  });
});

test("présente et transmet la désactivation scellée sans exposer les accès", async () => {
  const repository = repositoryWithPermission(IDENTITY_DISABLEMENT_PERMISSION);
  const disablement = [
    { ...identities[0], canSuspend: false },
    { ...identities[1], canSuspend: false, canDisable: true },
  ];
  let disabled;
  await withServer({
    repository,
    identityStateManagement: {
      listLifecycle: async () => disablement,
      disable: async (input) => {
        disabled = input;
        return { revokedSessions: 2, revokedAssignments: 3 };
      },
    },
  }, async (origin) => {
    const page = await fetch(`${origin}/admin/identities`, { headers: { cookie: sessionCookie() } });
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Désactiver et révoquer tous les accès/);
    assert.match(html, /n’est pas réversible depuis cette console/);
    assert.doesNotMatch(html, /assignment_id|session_id/);
    const target = html.match(/action="\/admin\/identities\/disable"[\s\S]*?name="target" value="([^"]+)"/)?.[1];
    assert.ok(target);
    const response = await fetch(`${origin}/admin/identities/disable`, {
      method: "POST", redirect: "manual",
      headers: { cookie: sessionCookie(), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        csrf, target, justification: "Sortie définitive confirmée après contrôle humain complet des accès",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/identities");
  });
  assert.deepEqual(disabled, {
    operatorIdentityId: operatorId, targetIdentityId: targetId, expectedStatus: "active",
    justification: "Sortie définitive confirmée après contrôle humain complet des accès",
  });
});
