import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { hashEmailLoginToken } from "./email-login.mjs";
import { createHttpHandler } from "./http.mjs";
import { OIDC_SESSION_COOKIE, open } from "./oidc.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://prod-admin.nsktech.fr/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

const identity = {
  identityId: "7aafad35-51e9-4e09-aa38-9c7900114125",
  email: "f.travers@nsktech.fr", displayName: "Fred TRAVERS", status: "active",
};

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, createAuditEvent({
    action: "identity.created", result: "success", source: "email-login-http-tests",
    correlationId: randomUUID(), subjectId: identity.identityId,
  }));
  return repository;
}

async function withServer(options, operation) {
  const server = createServer(createHttpHandler(options));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await operation(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("propose le courriel dans le sélecteur commun sans masquer les autres choix", async () => {
  const repository = seededRepository();
  await withServer({
    repository, oidcConfig, portalOrigins: ["https://nsktech.fr"], sessionAuthority: {},
    emailLogin: {
      enabled: true, publicOrigin: "https://prod-admin.nsktech.fr",
      delivery: { enabled: true, send: async () => {} },
    },
  }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/portal/login?return_to=${encodeURIComponent("https://nsktech.fr/#applications")}`);
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Courriel <span class="pill">Disponible/);
    assert.match(body, /action="\/auth\/email\/request"/);
    assert.match(body, /Infomaniak <span class="pill">Disponible/);
    assert.match(body, /Google <span class="pill inactive">Prévu/);
  });
});

test("crée une session centrale par lien et refuse le rejeu", async () => {
  const repository = seededRepository();
  let deliveredUrl = null;
  await withServer({
    repository, oidcConfig, portalOrigins: ["https://nsktech.fr"],
    emailLogin: {
      enabled: true, publicOrigin: "https://prod-admin.nsktech.fr",
      delivery: { enabled: true, send: async ({ loginUrl }) => { deliveredUrl = loginUrl; } },
    },
  }, async (baseUrl) => {
    const form = new URLSearchParams({ email: identity.email, return_to: "/account/sessions?theme=dark" });
    const requested = await fetch(`${baseUrl}/auth/email/request`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form,
    });
    assert.equal(requested.status, 202);
    assert.match(await requested.text(), /ne révèle jamais si une adresse est enregistrée/);
    assert.ok(deliveredUrl);

    const delivered = new URL(deliveredUrl);
    const opened = await fetch(`${baseUrl}${delivered.pathname}${delivered.search}`, { redirect: "manual" });
    assert.equal(opened.status, 303);
    assert.equal(opened.headers.get("location"), "/auth/email/confirm");
    const confirmationCookie = opened.headers.get("set-cookie").match(/n09_email_login_confirmation=([^;]+)/)[1];
    const rawToken = delivered.searchParams.get("token");
    assert.equal(repository.getEmailLoginToken(hashEmailLoginToken(rawToken)).status, "issued");

    const confirmed = await fetch(`${baseUrl}/auth/email/confirm`, {
      headers: { cookie: `n09_email_login_confirmation=${confirmationCookie}` },
    });
    const confirmationPage = await confirmed.text();
    assert.equal(confirmed.status, 200);
    assert.match(confirmationPage, /Me connecter/);
    assert.doesNotMatch(confirmationPage, new RegExp(rawToken));

    const consumed = await fetch(`${baseUrl}/auth/email/consume`, {
      method: "POST", redirect: "manual",
      headers: { cookie: `n09_email_login_confirmation=${confirmationCookie}` },
    });
    assert.equal(consumed.status, 303);
    assert.equal(consumed.headers.get("location"), "/account/sessions?theme=dark");
    const cookieHeader = consumed.headers.get("set-cookie");
    assert.match(cookieHeader, new RegExp(`${OIDC_SESSION_COOKIE}=`));
    const sealed = cookieHeader.match(new RegExp(`${OIDC_SESSION_COOKIE}=([^;]+)`))[1];
    const session = open(sealed, oidcConfig.sessionSecret, "oidc-session");
    assert.equal(session.identityId, identity.identityId);
    assert.equal(session.providerKey, "email");

    const status = await fetch(`${baseUrl}/auth/session`, {
      headers: { cookie: `${OIDC_SESSION_COOKIE}=${sealed}` },
    });
    assert.deepEqual(await status.json(), {
      authenticated: true, provider: "email", status: "authenticated",
      display_name: identity.displayName, request_id: null,
    });

    const replay = await fetch(`${baseUrl}${delivered.pathname}${delivered.search}`);
    assert.equal(replay.status, 400);
    assert.match(await replay.text(), /Lien invalide ou expiré/);
  });
});

test("donne la même réponse publique à une adresse inconnue", async () => {
  const repository = seededRepository();
  let deliveries = 0;
  await withServer({
    repository, oidcConfig,
    emailLogin: {
      enabled: true, publicOrigin: "https://prod-admin.nsktech.fr",
      delivery: { enabled: true, send: async () => { deliveries += 1; } },
    },
  }, async (baseUrl) => {
    const form = new URLSearchParams({ email: "inconnue@example.test", return_to: "/" });
    const response = await fetch(`${baseUrl}/auth/email/request`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form,
    });
    assert.equal(response.status, 202);
    assert.match(await response.text(), /Si cette adresse correspond à une identité NSK active/);
    assert.equal(deliveries, 0);
    assert.equal(repository.listIdentities().length, 1);
  });
});

test("les entrées Compte et application passent par le sélecteur commun", async () => {
  const repository = seededRepository();
  await withServer({ repository, oidcConfig, portalOrigins: ["https://nsktech.fr"] }, async (baseUrl) => {
    const account = await fetch(`${baseUrl}/portal/account?return_to=${encodeURIComponent("https://nsktech.fr/#applications")}`, { redirect: "manual" });
    assert.equal(account.status, 303);
    assert.match(account.headers.get("location"), /^\/auth\/login\?return_to=/);
    assert.doesNotMatch(account.headers.get("location"), /infomaniak/);

    const query = new URLSearchParams({
      client_id: "n09-suivi-taches", redirect_uri: "https://prod-taches.nsktech.fr/auth/callback",
      response_type: "code", code_challenge: "A".repeat(43), code_challenge_method: "S256",
      state: "opaque-state-value-with-32-characters",
    });
    const application = await fetch(`${baseUrl}/application-login/authorize?${query}`, { redirect: "manual" });
    assert.equal(application.status, 303);
    assert.match(application.headers.get("location"), /^\/auth\/login\?return_to=/);
    assert.doesNotMatch(application.headers.get("location"), /infomaniak/);
  });
});
