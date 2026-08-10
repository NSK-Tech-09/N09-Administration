import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import { createHttpHandler } from "./http.mjs";
import { ADMIN_APPLICATION_ID, LINK_DECISION_PERMISSION } from "./identity-link-admin.mjs";
import { createInternalClientAuthenticator, INTERNAL_CLIENT_HEADERS, signInternalRequest } from "./internal-client-auth.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

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

const adminIdentity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", email: "admin@example.test",
  displayName: "Admin NSK", status: "active",
};
const targetIdentity = {
  identityId: "70a40cd7-f2a4-4393-8021-9f806b42b41b", email: "target@example.test",
  displayName: "Cible NSK", status: "active",
};
const adminAudit = (action, changes = {}) => createAuditEvent({
  action, result: "success", source: "http-tests", correlationId: randomUUID(),
  justification: "Test HTTP reproductible", ...changes,
});

function seededAdminRepository({
  withPermission = true,
  withAccessRead = false,
  withAccessDecision = false,
  subject = "provider-subject-secret",
} = {}) {
  const adminRepository = new TransactionalMemoryRepository();
  adminRepository.saveIdentity(adminIdentity, adminAudit("identity.created", { subjectId: adminIdentity.identityId }));
  adminRepository.saveIdentity(targetIdentity, adminAudit("identity.created", { subjectId: targetIdentity.identityId }));
  adminRepository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, adminAudit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  if (withPermission) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "identity-link-administrator", permissions: [LINK_DECISION_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de l’administration", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  if (withAccessRead) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-directory-reader", permissions: [ACCESS_DIRECTORY_READ_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de la consultation des accès", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  if (withAccessDecision) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-decision-administrator", permissions: [ACCESS_DECISION_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test des décisions d’accès", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  const linkRequest = createLinkRequest({
    issuer: "https://login.infomaniak.com", subject, providerKey: "infomaniak",
    emailHint: "candidate@example.test", displayNameHint: "Personne candidate",
  });
  adminRepository.saveLinkRequest(linkRequest, adminAudit("external_identity.link_requested"));
  return { adminRepository, linkRequest };
}

function adminCookie(csrf = "csrf-value") {
  const session = {
    issuer: "https://login.infomaniak.com", subject: "admin-provider-subject",
    identityId: adminIdentity.identityId, displayName: adminIdentity.displayName,
    status: "authenticated", csrf, expiresAt: Date.now() + 60_000,
  };
  return `${OIDC_SESSION_COOKIE}=${seal(session, oidcConfig.sessionSecret, "oidc-session")}`;
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

test("refuse l’administration à une identité rattachée sans permission dédiée", async () => {
  const { adminRepository } = seededAdminRepository({ withPermission: false });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/link-requests`, { headers: { cookie: adminCookie() } });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /Aucun droit implicite/);
  });
});

test("affiche les demandes sans exposer le sujet technique du fournisseur", async () => {
  const { adminRepository, linkRequest } = seededAdminRepository();
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/link-requests`, { headers: { cookie: adminCookie() } });
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, new RegExp(linkRequest.requestId));
    assert.match(body, /Personne candidate|candidate@example\.test/);
    assert.doesNotMatch(body, /provider-subject-secret/);
  });
});

test("sépare la consultation des accès du pouvoir de décision sur les rattachements", async () => {
  const { adminRepository } = seededAdminRepository({ withPermission: true, withAccessRead: false });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access`, { headers: { cookie: adminCookie() } });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /permission dédiée à la consultation des accès/);
  });
});

test("affiche le registre en lecture seule avec identités, applications et affectations", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessRead: true });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access`, { headers: { cookie: adminCookie() } });
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Utilisateurs et accès/);
    assert.match(body, /Admin NSK/);
    assert.match(body, /N09 – Administration/);
    assert.match(body, /access-directory-reader/);
    assert.match(body, /administration:access:read/);
    assert.match(body, /lecture seule/);
    assert.doesNotMatch(body, /provider-subject-secret/);
    assert.doesNotMatch(body, /target_identity_id|justification/);
  });
});

test("refuse toute écriture sur le registre de consultation", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessRead: true });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access`, {
      method: "POST", headers: { cookie: adminCookie() },
    });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET");
  });
});

test("sépare le pouvoir de révocation de la simple consultation", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessRead: true, withAccessDecision: false });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access-decisions`, { headers: { cookie: adminCookie() } });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /permission dédiée aux décisions d’accès/);
  });
});

test("révoque une affectation centrale avec CSRF, version et audit", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessDecision: true });
  adminRepository.saveApplication({
    applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches",
    status: "active", registrationPolicy: "closed",
  }, adminAudit("application.registered", { applicationId: "n09-suivi-taches" }));
  const assignmentId = "80a40cd7-f2a4-4393-8021-9f806b42b41c";
  adminRepository.saveAssignment({
    assignmentId, subjectId: targetIdentity.identityId, applicationId: "n09-suivi-taches",
    roleId: "tasks-reader", permissions: ["tasks:read"], scopeType: null, scopeId: null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason: "Accès initial contrôlé", decidedBy: adminIdentity.identityId,
    inheritedFromGroup: null, version: 1,
  }, adminAudit("assignment.created", { subjectId: targetIdentity.identityId, applicationId: "n09-suivi-taches" }));

  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const page = await fetch(`${baseUrl}/admin/access-decisions`, { headers: { cookie: adminCookie() } });
    const body = await page.text();
    const [decisionAuthority] = adminRepository.listAssignments(adminIdentity.identityId, ADMIN_APPLICATION_ID)
      .filter((item) => item.permissions.includes(ACCESS_DECISION_PERMISSION));
    assert.equal(page.status, 200);
    assert.match(body, /Décider les révocations d’accès/);
    assert.match(body, new RegExp(assignmentId));
    assert.match(body, /Aucun accès ne peut être accordé/);
    assert.match(body, /Pouvoir protégé/);
    assert.doesNotMatch(body, new RegExp(`/admin/access-decisions/${decisionAuthority.assignmentId}/revoke`));

    const forged = await fetch(`${baseUrl}/admin/access-decisions/${assignmentId}/revoke`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie("expected-csrf"), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({
        csrf: "forged-csrf", expected_version: "1",
        justification: "Retrait demandé après fin du besoin applicatif",
      }),
    });
    assert.equal(forged.status, 403);
    assert.equal(adminRepository.listAssignments(targetIdentity.identityId, "n09-suivi-taches")[0].status, "active");

    const auditBefore = adminRepository.auditCount();
    const response = await fetch(`${baseUrl}/admin/access-decisions/${assignmentId}/revoke`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({
        csrf: "csrf-value", expected_version: "1",
        justification: "Retrait demandé après fin du besoin applicatif",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/access-decisions");
    assert.equal(adminRepository.auditCount(), auditBefore + 1);
  });
  const [revoked] = adminRepository.listAssignments(targetIdentity.identityId, "n09-suivi-taches");
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.version, 2);
  assert.equal(revoked.decidedBy, adminIdentity.identityId);
  assert.equal(adminRepository.verifyAuditChain(), true);
});

test("réserve le pouvoir de décision à une gouvernance dédiée", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessDecision: true });
  const [lastDecider] = adminRepository.listAssignments(adminIdentity.identityId, ADMIN_APPLICATION_ID)
    .filter((item) => item.permissions.includes(ACCESS_DECISION_PERMISSION));
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access-decisions/${lastDecider.assignmentId}/revoke`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({
        csrf: "csrf-value", expected_version: "1",
        justification: "Passage de relais du pouvoir de décision central",
      }),
    });
    assert.equal(response.status, 409);
  });
  assert.equal(adminRepository.listAssignments(adminIdentity.identityId, ADMIN_APPLICATION_ID)
    .find((item) => item.assignmentId === lastDecider.assignmentId).status, "active");
});

test("bloque une décision dont la preuve CSRF est incorrecte", async () => {
  const { adminRepository, linkRequest } = seededAdminRepository();
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/link-requests/${linkRequest.requestId}/approve`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie("expected-csrf"), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({ csrf: "forged-csrf", target_identity_id: targetIdentity.identityId, justification: "Test" }),
    });
    assert.equal(response.status, 403);
    assert.equal(adminRepository.getLinkRequest(linkRequest.requestId).status, "pending");
  });
});

test("approuve un rattachement justifié et audité sans accorder de rôle", async () => {
  const { adminRepository, linkRequest } = seededAdminRepository();
  const auditBefore = adminRepository.auditCount();
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/link-requests/${linkRequest.requestId}/approve`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({ csrf: "csrf-value", target_identity_id: targetIdentity.identityId, justification: "Identité vérifiée" }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/link-requests");
  });
  assert.equal(adminRepository.getLinkRequest(linkRequest.requestId).status, "approved");
  assert.equal(adminRepository.listAssignments(targetIdentity.identityId, ADMIN_APPLICATION_ID).length, 0);
  assert.equal(adminRepository.auditCount(), auditBefore + 1);
  assert.equal(adminRepository.verifyAuditChain(), true);
});

test("refuse une demande avec justification et trace la décision", async () => {
  const { adminRepository, linkRequest } = seededAdminRepository();
  const auditBefore = adminRepository.auditCount();
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/link-requests/${linkRequest.requestId}/reject`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({ csrf: "csrf-value", justification: "Preuve insuffisante" }),
    });
    assert.equal(response.status, 303);
  });
  assert.equal(adminRepository.getLinkRequest(linkRequest.requestId).status, "rejected");
  assert.equal(adminRepository.auditCount(), auditBefore + 1);
  assert.equal(adminRepository.verifyAuditChain(), true);
});

test("n'expose un code OIDC sûr que lorsque le banc de validation l'autorise", async () => {
  await withServer({ oidcConfig: { ...oidcConfig, exposeSafeErrors: true } }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/infomaniak/callback`);
    const body = await response.text();
    assert.equal(response.status, 400);
    assert.match(body, /incomplete_oidc_callback/);
    assert.doesNotMatch(body, /client-secret|session-secret/);
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
  const savedRequests = [];
  const linkRepository = {
    ...repository,
    findExternalIdentity: async () => null,
    findActiveLinkRequest: async () => null,
    saveLinkRequest: async (request) => savedRequests.push(request),
  };
  await withServer({ repository: linkRepository, oidcConfig, fetchImpl }, async (baseUrl) => {
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
    assert.equal(savedRequests.length, 1);
    assert.equal(savedRequests[0].status, "pending");
    assert.equal(savedRequests[0].subject, "external-42");
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

test("accepte la décision signée par l’identité technique et bloque son rejeu", async () => {
  const clientId = "tasks-preprod";
  const secret = "a-protected-test-secret-with-at-least-32-characters";
  const timestamp = String(Date.now());
  const nonce = randomUUID();
  const rawBody = JSON.stringify(payload);
  const signature = signInternalRequest(secret, {
    method: "POST", pathname: "/internal/v1/access-decisions", timestamp, nonce, rawBody,
  });
  const headers = {
    "content-type": "application/json",
    [INTERNAL_CLIENT_HEADERS.clientId]: clientId,
    [INTERNAL_CLIENT_HEADERS.timestamp]: timestamp,
    [INTERNAL_CLIENT_HEADERS.nonce]: nonce,
    [INTERNAL_CLIENT_HEADERS.signature]: signature,
  };
  const authenticate = createInternalClientAuthenticator({
    clients: new Map([[clientId, { applicationId: "tasks", secret }]]),
  });
  await withServer({ authenticate }, async (baseUrl) => {
    const accepted = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers, body: rawBody,
    });
    assert.equal(accepted.status, 200);
    assert.deepEqual(await accepted.json(), { allowed: true, reason_code: "access_granted" });

    const replayed = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST", headers, body: rawBody,
    });
    assert.equal(replayed.status, 401);
    assert.deepEqual(await replayed.json(), { error: "authentication_required" });
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
