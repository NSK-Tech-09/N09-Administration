import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createApplicationSessionAuthority } from "./application-session-authority.mjs";
import { createHttpHandler } from "./http.mjs";
import { cookie, OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";
import { bootstrapPortalProduction } from "./portal-production-bootstrap.mjs";
import { PORTAL_APPLICATION_ID, PORTAL_SESSION_COOKIE } from "./portal-session-broker.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const portalOrigin = "https://nsktech.example.test";
const sessionSecret = "S".repeat(48);
const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "fred@example.test", displayName: "Fred", status: "active",
};
const oidcConfig = {
  clientId: "portal-http-test", clientSecret: "not-a-secret",
  redirectUri: "https://admin.example.test/auth/infomaniak/callback", sessionSecret,
};
const audit = (action, applicationId = null) => createAuditEvent({
  action, result: "success", source: "portal-http-tests", correlationId: randomUUID(),
  subjectId: identity.identityId, applicationId, justification: "Préparation de la recette HTTP du portail",
});

async function seeded() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created"));
  await bootstrapPortalProduction(repository, {
    database: "n09_admin_prod", allowBootstrap: "true", identityId: identity.identityId,
    justification: "Activation contrôlée du portail pour la recette HTTP de production",
  });
  repository.saveApplication({
    applicationId: "n09-energie", displayName: "N09 – Énergie", status: "active", registrationPolicy: "closed",
  }, audit("application.registered", "n09-energie"));
  repository.saveAssignment({
    assignmentId: randomUUID(), subjectId: identity.identityId, applicationId: "n09-energie",
    roleId: "energy-reader", permissions: ["energy:read"], scopeType: null, scopeId: null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason: "Accès Énergie de la recette portail", decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", "n09-energie"));
  const authority = createApplicationSessionAuthority({
    repository,
    config: {
      mode: "enforce", applicationId: PORTAL_APPLICATION_ID,
      idleTtlMs: 3_600_000, absoluteTtlMs: 14_400_000, touchIntervalMs: 300_000,
    },
  });
  return { repository, authority };
}

function identityCookie() {
  const value = seal({
    sessionVersion: 2, status: "authenticated", identityId: identity.identityId,
    displayName: identity.displayName, csrf: randomUUID(), expiresAt: Date.now() + 60_000,
  }, sessionSecret, "oidc-session");
  return cookie(OIDC_SESSION_COOKIE, value, { maxAge: 60 });
}

async function withServer(operation) {
  const { repository, authority } = await seeded();
  const server = createServer(createHttpHandler({
    repository, oidcConfig, sessionAuthority: authority, portalOrigins: [portalOrigin],
  }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    await operation(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("ouvre une session portail dédiée puis restitue le catalogue personnel", async () => {
  await withServer(async (origin) => {
    const login = await fetch(`${origin}/portal/login?return_to=${encodeURIComponent(`${portalOrigin}/#applications`)}`, {
      headers: { cookie: identityCookie() }, redirect: "manual",
    });
    assert.equal(login.status, 303);
    assert.equal(login.headers.get("location"), `${portalOrigin}/#applications`);
    const setCookie = login.headers.get("set-cookie");
    assert.match(setCookie, new RegExp(`${PORTAL_SESSION_COOKIE}=`));
    assert.match(setCookie, /Path=\/portal/);
    const portalCookie = setCookie.match(new RegExp(`${PORTAL_SESSION_COOKIE}=([^;]+)`))[0];
    const session = await fetch(`${origin}/portal/session`, {
      headers: { origin: portalOrigin, cookie: portalCookie },
    });
    assert.equal(session.status, 200);
    assert.equal(session.headers.get("access-control-allow-origin"), portalOrigin);
    assert.deepEqual(await session.json(), {
      authenticated: true,
      user: { displayName: "Fred", email: "fred@example.test" },
      applications: ["n09-energie"],
    });
  });
});

test("révoque réellement la session portail et refuse les origines étrangères", async () => {
  await withServer(async (origin) => {
    const forbidden = await fetch(`${origin}/portal/session`, { headers: { origin: "https://evil.example.test" } });
    assert.equal(forbidden.status, 403);
    const login = await fetch(`${origin}/portal/login?return_to=${encodeURIComponent(`${portalOrigin}/`)}`, {
      headers: { cookie: identityCookie() }, redirect: "manual",
    });
    const portalCookie = login.headers.get("set-cookie").match(new RegExp(`${PORTAL_SESSION_COOKIE}=([^;]+)`))[0];
    const logout = await fetch(`${origin}/portal/logout?return_to=${encodeURIComponent(`${portalOrigin}/`)}`, {
      method: "POST", headers: { origin: portalOrigin, cookie: portalCookie }, redirect: "manual",
    });
    assert.equal(logout.status, 303);
    assert.equal(logout.headers.get("location"), `${portalOrigin}/`);
    const rejected = await fetch(`${origin}/portal/session`, {
      headers: { origin: portalOrigin, cookie: portalCookie },
    });
    assert.equal(rejected.status, 401);
  });
});
