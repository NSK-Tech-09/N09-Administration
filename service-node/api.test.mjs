import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAccessRequest, evaluateAccessRequestAsync } from "./api.mjs";

const identity = { identityId: "identity-1", status: "active" };
const application = { applicationId: "tasks", status: "active" };
const assignment = {
  subjectId: "identity-1", applicationId: "tasks", roleId: "reader",
  permissions: ["tasks:read"], scopeType: "site", scopeId: "site-09",
  conditions: [], status: "active", validFrom: null, validUntil: null,
};
const repository = {
  getIdentity: (id) => id === identity.identityId ? identity : null,
  getApplication: (id) => id === application.applicationId ? application : null,
  listAssignments: () => [assignment],
};
const principal = { applicationId: "tasks", audience: "tasks", correlationId: "correlation-1" };
const payload = { identity_id: "identity-1", application_id: "tasks", required_permission: "tasks:read", scope_type: "site", scope_id: "site-09", satisfied_conditions: [] };

test("refuse une requête anonyme", () => {
  assert.equal(evaluateAccessRequest({ repository, principal: null, payload }).status, 401);
});
test("refuse une audience étrangère", () => {
  assert.equal(evaluateAccessRequest({ repository, principal: { ...principal, audience: "energy" }, payload }).status, 403);
});
test("refuse un champ inconnu", () => {
  assert.equal(evaluateAccessRequest({ repository, principal, payload: { ...payload, password: "interdit" } }).status, 400);
});
test("renvoie une absence neutre", () => {
  const response = evaluateAccessRequest({ repository, principal, payload: { ...payload, identity_id: "unknown" } });
  assert.deepEqual(response.body, { error: "resource_not_found" });
});
test("renvoie une décision contextualisée et son identifiant de corrélation", () => {
  const response = evaluateAccessRequest({ repository, principal, payload });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { allowed: true, reason_code: "access_granted" });
  assert.equal(response.correlationId, "correlation-1");
});
test("un refus métier reste une décision HTTP réussie", () => {
  const response = evaluateAccessRequest({ repository, principal, payload: { ...payload, scope_id: "site-11" } });
  assert.equal(response.status, 200);
  assert.equal(response.body.allowed, false);
});

test("la frontière asynchrone conserve exactement la décision", async () => {
  const asynchronousRepository = {
    getIdentity: async (id) => repository.getIdentity(id),
    getApplication: async (id) => repository.getApplication(id),
    listAssignments: async (...args) => repository.listAssignments(...args),
  };
  const response = await evaluateAccessRequestAsync({ repository: asynchronousRepository, principal, payload });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { allowed: true, reason_code: "access_granted" });
  assert.equal(response.correlationId, "correlation-1");
});

test("rend la preuve de session applicative opposable avant le calcul des droits", async () => {
  const asynchronousRepository = {
    getIdentity: async (id) => repository.getIdentity(id),
    getApplication: async (id) => repository.getApplication(id),
    listAssignments: async (...args) => repository.listAssignments(...args),
  };
  let credential;
  const sessionAuthority = {
    assess: async (request) => {
      credential = request.credential;
      return { allowed: false, reasonCode: "session_revoked" };
    },
  };
  const response = await evaluateAccessRequestAsync({
    repository: asynchronousRepository,
    principal,
    sessionAuthority,
    payload: { ...payload, session_id: "session-1", session_secret: "secret-1" },
  });
  assert.deepEqual(credential, { sessionId: "session-1", secret: "secret-1" });
  assert.deepEqual(response.body, { allowed: false, reason_code: "session_revoked" });
  assert.equal(response.status, 200);
});

test("refuse une preuve de session partielle avant toute consultation", async () => {
  const response = await evaluateAccessRequestAsync({
    repository,
    principal,
    payload: { ...payload, session_id: "session-1" },
  });
  assert.equal(response.status, 400);
});
