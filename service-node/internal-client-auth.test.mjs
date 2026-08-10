import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  createInternalClientAuthenticator, internalClientsFromEnvironment,
  INTERNAL_CLIENT_HEADERS, signInternalRequest,
} from "./internal-client-auth.mjs";

const secret = "a-protected-test-secret-with-at-least-32-characters";
const clientId = "tasks-preprod";
const applicationId = "n09-suivi-taches";
const now = 1_786_358_400_000;

function signedRequest({ body = '{"identity_id":"identity-1"}', timestamp = String(now), nonce = randomUUID() } = {}) {
  const request = { method: "POST", url: "/internal/v1/access-decisions", headers: {} };
  const signature = signInternalRequest(secret, {
    method: request.method, pathname: request.url, timestamp, nonce, rawBody: body,
  });
  request.headers = {
    [INTERNAL_CLIENT_HEADERS.clientId]: clientId,
    [INTERNAL_CLIENT_HEADERS.timestamp]: timestamp,
    [INTERNAL_CLIENT_HEADERS.nonce]: nonce,
    [INTERNAL_CLIENT_HEADERS.signature]: signature,
  };
  return { request, body };
}

test("authentifie l’application technique et lie la signature au corps", async () => {
  const authenticate = createInternalClientAuthenticator({
    clients: new Map([[clientId, { applicationId, secret }]]), now: () => now,
  });
  const { request, body } = signedRequest();
  assert.deepEqual(await authenticate(request, { rawBody: body }), { applicationId, audience: applicationId });
});

test("refuse une requête rejouée, périmée ou altérée", async () => {
  const authenticate = createInternalClientAuthenticator({
    clients: new Map([[clientId, { applicationId, secret }]]), now: () => now,
  });
  const signed = signedRequest();
  assert.ok(await authenticate(signed.request, { rawBody: signed.body }));
  assert.equal(await authenticate(signed.request, { rawBody: signed.body }), null);
  const expired = signedRequest({ timestamp: String(now - 30_001) });
  assert.equal(await authenticate(expired.request, { rawBody: expired.body }), null);
  const altered = signedRequest();
  assert.equal(await authenticate(altered.request, { rawBody: "{}" }), null);
});

test("verrouille une configuration partielle ou un secret trop court", () => {
  assert.equal(internalClientsFromEnvironment({}).size, 0);
  assert.throws(() => internalClientsFromEnvironment({ N09_TASKS_INTERNAL_CLIENT_ID: clientId }), /invalid/);
  assert.throws(() => internalClientsFromEnvironment({
    N09_TASKS_INTERNAL_CLIENT_ID: clientId, N09_TASKS_INTERNAL_CLIENT_SECRET: "short",
  }), /invalid/);
});
