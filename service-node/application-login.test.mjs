import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  exchangeApplicationLoginCode, issueApplicationLoginCode, validateAuthorizationRequest, verifierChallenge,
} from "./application-login.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = { identityId: randomUUID(), email: "fred@example.test", displayName: "Fred", status: "active" };
const application = { applicationId: "n09-suivi-taches", displayName: "Suivi", status: "active", registrationPolicy: "closed" };
const redirectUri = "https://preprod-taches.example.test/auth/nsk/callback";
const audit = (action, fields) => createAuditEvent({
  action, result: "success", source: "application-login-tests", correlationId: randomUUID(),
  justification: "Préparation du parcours de connexion applicative", ...fields,
});

function seeded() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  repository.saveApplication(application, audit("application.registered", { applicationId: application.applicationId }));
  repository.saveApplicationRedirectUri(application.applicationId, redirectUri,
    audit("application.redirect_uri_registered", { applicationId: application.applicationId }));
  repository.saveApplicationLoginPolicy(application.applicationId, "tasks:read",
    audit("application.login_policy_registered", { applicationId: application.applicationId }));
  repository.saveAssignment({
    assignmentId: randomUUID(), subjectId: identity.identityId, applicationId: application.applicationId,
    roleId: "reader", permissions: ["tasks:read"], scopeType: null, scopeId: null,
    conditions: [], status: "active", validFrom: null, validUntil: null, reason: "test",
    decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: identity.identityId, applicationId: application.applicationId }));
  return repository;
}

function request(verifier = "a".repeat(64)) {
  return {
    applicationId: application.applicationId, redirectUri, state: "s".repeat(43),
    codeChallenge: verifierChallenge(verifier),
  };
}

test("émet puis consomme une seule fois un code lié à PKCE et à l’application", async () => {
  const repository = seeded();
  const verifier = "v".repeat(64);
  const { code } = await issueApplicationLoginCode({
    repository, session: { status: "authenticated", identityId: identity.identityId }, request: request(verifier),
  });
  const principal = { applicationId: application.applicationId, audience: application.applicationId };
  const payload = { code, code_verifier: verifier, redirect_uri: redirectUri, client_id: application.applicationId };
  assert.deepEqual(await exchangeApplicationLoginCode({ repository, principal, payload }), {
    identity_id: identity.identityId, display_name: identity.displayName, email: identity.email,
    application_id: application.applicationId,
  });
  await assert.rejects(exchangeApplicationLoginCode({ repository, principal, payload }), /consumed/);
});

test("un mauvais PKCE ne consomme pas le code légitime", async () => {
  const repository = seeded();
  const verifier = "v".repeat(64);
  const { code } = await issueApplicationLoginCode({
    repository, session: { status: "authenticated", identityId: identity.identityId }, request: request(verifier),
  });
  const principal = { applicationId: application.applicationId, audience: application.applicationId };
  const base = { code, redirect_uri: redirectUri, client_id: application.applicationId };
  await assert.rejects(exchangeApplicationLoginCode({ repository, principal, payload: { ...base, code_verifier: "x".repeat(64) } }), /invalid/);
  assert.equal((await exchangeApplicationLoginCode({ repository, principal, payload: { ...base, code_verifier: verifier } })).identity_id, identity.identityId);
});

test("remet une preuve de session applicative uniquement par l'échange serveur à serveur", async () => {
  const repository = seeded();
  const verifier = "v".repeat(64);
  const { code } = await issueApplicationLoginCode({
    repository, session: { status: "authenticated", identityId: identity.identityId }, request: request(verifier),
  });
  const sessionAuthority = {
    issue: async ({ identityId, applicationId }) => {
      assert.equal(identityId, identity.identityId);
      assert.equal(applicationId, application.applicationId);
      return {
        credential: { sessionId: "00000000-0000-4000-8000-000000000042", secret: "S".repeat(43) },
        idleExpiresAt: "2026-08-13T09:00:00.000Z",
        absoluteExpiresAt: "2026-08-13T12:00:00.000Z",
      };
    },
  };
  const result = await exchangeApplicationLoginCode({
    repository,
    principal: { applicationId: application.applicationId, audience: application.applicationId },
    payload: { code, code_verifier: verifier, redirect_uri: redirectUri, client_id: application.applicationId },
    sessionAuthority,
  });
  assert.equal(result.session_id, "00000000-0000-4000-8000-000000000042");
  assert.equal(result.session_secret, "S".repeat(43));
  assert.equal(JSON.stringify(repository.auditSnapshot()).includes(result.session_secret), false);
});

test("refuse une adresse de retour non enregistrée et les demandes ambiguës", async () => {
  const repository = seeded();
  await assert.rejects(issueApplicationLoginCode({
    repository, session: { status: "authenticated", identityId: identity.identityId },
    request: { ...request(), redirectUri: "https://evil.example.test/auth/nsk/callback" },
  }), /redirect/);
  assert.throws(() => validateAuthorizationRequest(new URLSearchParams({ client_id: application.applicationId })), /invalid/);
});
