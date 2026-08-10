import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createHttpHandler } from "./http.mjs";

const identity = { identityId: "identity-1", status: "active" };
const application = { applicationId: "tasks", status: "active" };
const assignment = {
  subjectId: "identity-1", applicationId: "tasks", roleId: "reader",
  permissions: ["tasks:read"], scopeType: null, scopeId: null,
  conditions: [], status: "active", validFrom: null, validUntil: null,
};
const repository = {
  getIdentity: async (id) => id === identity.identityId ? identity : null,
  getApplication: async (id) => id === application.applicationId ? application : null,
  listAssignments: async () => [assignment],
};
const payload = {
  identity_id: "identity-1", application_id: "tasks",
  required_permission: "tasks:read", satisfied_conditions: [],
};
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

async function withServer(options, operation) {
  const server = createServer(createHttpHandler({ repository, ...options }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    await operation(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("expose une santé minimale sans information interne", async () => {
  await withServer({}, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
    assert.equal(response.headers.get("cache-control"), "no-store");
  });
});

test("présente le portail et démarre le parcours Infomaniak sécurisé", async () => {
  await withServer({ oidcConfig }, async (baseUrl) => {
    const home = await fetch(`${baseUrl}/`);
    assert.equal(home.status, 200);
    assert.match(await home.text(), /Continuer avec Infomaniak/);
    assert.match(home.headers.get("content-security-policy"), /default-src 'none'/);

    const start = await fetch(`${baseUrl}/auth/infomaniak/start`, { redirect: "manual" });
    assert.equal(start.status, 302);
    assert.equal(new URL(start.headers.get("location")).hostname, "login.infomaniak.com");
    assert.match(start.headers.get("set-cookie"), /HttpOnly; Secure; SameSite=Lax/);
  });
});

test("ne révèle pas la preuve externe dans l'état de session public", async () => {
  await withServer({ oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { authenticated: false });
  });
});

test("valide le retour Infomaniak et crée seulement une session à rattacher", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  let expectedNonce;
  const fetchImpl = async (url) => {
    if (String(url).endsWith("/oauth2/jwks")) {
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }), { status: 200 });
    }
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key" })).toString("base64url");
    const claims = Buffer.from(JSON.stringify({
      iss: "https://login.infomaniak.com", aud: oidcConfig.clientId, sub: "external-42",
      name: "Personne de test", nonce: expectedNonce, iat: now - 1, exp: now + 300,
    })).toString("base64url");
    const signature = sign("RSA-SHA256", Buffer.from(`${header}.${claims}`), privateKey).toString("base64url");
    return new Response(JSON.stringify({ id_token: `${header}.${claims}.${signature}` }), { status: 200 });
  };
  await withServer({ oidcConfig, fetchImpl }, async (baseUrl) => {
    const start = await fetch(`${baseUrl}/auth/infomaniak/start`, { redirect: "manual" });
    const authorization = new URL(start.headers.get("location"));
    expectedNonce = authorization.searchParams.get("nonce");
    const transactionCookie = start.headers.get("set-cookie").split(";")[0];
    const callback = await fetch(`${baseUrl}/auth/infomaniak/callback?code=one-time-code&state=${authorization.searchParams.get("state")}`, {
      headers: { cookie: transactionCookie }, redirect: "manual",
    });
    assert.equal(callback.status, 303);
    assert.equal(callback.headers.get("location"), "/");
    const setCookie = callback.headers.get("set-cookie");
    assert.match(setCookie, /n09_oidc_transaction=;/);
    assert.match(setCookie, /n09_oidc_session=/);
    assert.doesNotMatch(setCookie, /external-42|Personne de test/);
  });
});

test("refuse par défaut une décision sans adaptateur d'authentification", async () => {
  await withServer({}, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "authentication_required" });
    assert.match(response.headers.get("x-correlation-id"), /^[0-9a-f-]{36}$/);
  });
});

test("transporte une décision authentifiée sans modifier son contrat", async () => {
  const authenticate = async () => ({
    applicationId: "tasks", audience: "tasks", correlationId: "00000000-0000-4000-8000-000000000009",
  });
  await withServer({ authenticate }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { allowed: true, reason_code: "access_granted" });
    assert.equal(response.headers.get("x-correlation-id"), "00000000-0000-4000-8000-000000000009");
  });
});

test("refuse les formats, méthodes et volumes non autorisés", async () => {
  await withServer({ maxBodyBytes: 16 }, async (baseUrl) => {
    const wrongMethod = await fetch(`${baseUrl}/internal/v1/access-decisions`);
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.get("allow"), "POST");

    const wrongType = await fetch(`${baseUrl}/internal/v1/access-decisions`, { method: "POST", body: "{}" });
    assert.equal(wrongType.status, 415);

    const tooLarge = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    assert.equal(tooLarge.status, 413);
  });
});

test("n'expose jamais le détail d'une panne interne", async () => {
  const authenticate = async () => { throw new Error("secret diagnostic"); };
  await withServer({ authenticate }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    assert.equal(response.status, 500);
    const responseText = await response.text();
    assert.deepEqual(JSON.parse(responseText), { error: "internal_error" });
    assert.doesNotMatch(responseText, /secret diagnostic/);
  });
});
