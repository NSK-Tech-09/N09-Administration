import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  authorizationRequest, INFOMANIAK_ENDPOINTS, INFOMANIAK_ISSUER, oidcConfigFromEnvironment,
  exchangeAuthorizationCode, open, pkceChallenge, seal, verifyIdToken,
} from "./oidc.mjs";

const config = {
  clientId: "n09-client", clientSecret: "protected-client-secret",
  redirectUri: "https://preprod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

function jwt(claims, privateKey, kid = "key-1") {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

test("chiffre les preuves temporaires et refuse un autre usage", () => {
  const sealed = seal({ state: "state", expiresAt: Date.now() + 1_000 }, config.sessionSecret, "transaction");
  assert.equal(open(sealed, config.sessionSecret, "transaction").state, "state");
  assert.throws(() => open(sealed, config.sessionSecret, "session"), /invalid_sealed_value/);
  assert.doesNotMatch(sealed, /state/);
});

test("construit une demande Authorization Code avec PKCE S256", () => {
  const request = authorizationRequest(config);
  assert.equal(request.url.origin + request.url.pathname, INFOMANIAK_ENDPOINTS.authorization);
  assert.equal(request.url.searchParams.get("response_type"), "code");
  assert.equal(request.url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(request.url.searchParams.get("code_challenge"), pkceChallenge(request.transaction.verifier));
  assert.equal(request.url.searchParams.get("nonce"), request.transaction.nonce);
});

test("impose HTTPS et un secret de session suffisamment long", () => {
  assert.throws(() => oidcConfigFromEnvironment({}), /missing_or_invalid_oidc_setting/);
  assert.throws(() => oidcConfigFromEnvironment({
    INFOMANIAK_CLIENT_ID: "id", INFOMANIAK_CLIENT_SECRET: "secret",
    INFOMANIAK_REDIRECT_URI: "http://example.invalid/callback", N09_SESSION_SECRET: config.sessionSecret,
  }), /oidc_redirect_must_use_https/);
});

test("échange le code avec les identifiants attendus dans le formulaire", async () => {
  let request;
  const fetchImpl = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ id_token: "signed-token" }), { status: 200 });
  };
  assert.equal(await exchangeAuthorizationCode({ code: "code-1", verifier: "verifier-1", config, fetchImpl }), "signed-token");
  const body = new URLSearchParams(request.options.body);
  assert.equal(request.url, INFOMANIAK_ENDPOINTS.token);
  assert.equal(request.options.headers.authorization, undefined);
  assert.equal(body.get("client_id"), config.clientId);
  assert.equal(body.get("client_secret"), config.clientSecret);
  assert.equal(body.get("code_verifier"), "verifier-1");
});

test("vérifie signature RS256, émetteur, audience, dates et nonce", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const now = Date.now();
  const claims = {
    iss: INFOMANIAK_ISSUER, aud: config.clientId, sub: "external-42", nonce: "nonce-42",
    iat: Math.floor(now / 1000) - 5, exp: Math.floor(now / 1000) + 300,
  };
  const token = jwt(claims, privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  const fetchImpl = async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "key-1", alg: "RS256" }] }), { status: 200 });
  assert.equal((await verifyIdToken(token, { clientId: config.clientId, nonce: "nonce-42", fetchImpl, now })).sub, "external-42");
  await assert.rejects(verifyIdToken(token, { clientId: config.clientId, nonce: "wrong", fetchImpl, now }), /invalid_id_token_nonce/);
});
