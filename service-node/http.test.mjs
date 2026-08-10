import assert from "node:assert/strict";
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
