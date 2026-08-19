import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ACCESS_DIRECTORY_READ_PERMISSION } from "./access-admin.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import { createHttpHandler } from "./http.mjs";
import { ADMIN_APPLICATION_ID, LINK_DECISION_PERMISSION } from "./identity-link-admin.mjs";
import { createInternalClientAuthenticator, INTERNAL_CLIENT_HEADERS, signInternalRequest } from "./internal-client-auth.mjs";
import { OIDC_SESSION_COOKIE, open, seal } from "./oidc.mjs";
import { NOTIFICATION_OPERATIONS_READ_PERMISSION } from "./notification-operations-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

test("synchronise le bandeau Administration avec la validité réelle de la session", () => {
  const source = readFileSync(new URL("./assets/theme.js", import.meta.url), "utf8");
  const httpSource = readFileSync(new URL("./http.mjs", import.meta.url), "utf8");
  assert.match(source, /fetch\("\/auth\/session", \{ credentials: "include", cache: "no-store" \}\)/);
  assert.match(source, /response\.status !== 401/);
  assert.match(source, /authenticationUnavailable/);
  assert.match(source, /window\.location\.pathname === "\/account"/);
  assert.match(source, /window\.location\.replace\(loginHref\)/);
  assert.match(source, /previousAuthenticationState === true && !authenticated/);
  assert.match(source, /window\.location\.reload\(\)/);
  assert.match(source, /window\.setInterval\(refresh, 60_000\)/);
  assert.match(source, /document\.addEventListener\("visibilitychange", refreshWhenVisible\)/);
  assert.match(httpSource, /href="\/account">Mon compte<\/a>/);
  assert.match(httpSource, /option value="\/account">Mon compte<\/option>/);
  assert.match(httpSource, /theme\.js\?v=0\.2\.3/);
  assert.match(httpSource, /\[hidden\]\{display:none!important\}/);
});

test("revalide le script de session au lieu de conserver son ancienne version", async () => {
  await withServer({}, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/assets/theme.js`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-cache");
  });
});

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
  withNotificationOperations = false,
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
  if (withNotificationOperations) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "notification-operations-reader", permissions: [NOTIFICATION_OPERATIONS_READ_PERMISSION],
      scopeType: null, scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de l’exploitation des notifications", decidedBy: adminIdentity.identityId,
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

function adminCookie(csrf = "csrf-value", centralSession = null, sessionVersion = 2) {
  const session = {
    issuer: "https://login.infomaniak.com", subject: "admin-provider-subject",
    identityId: adminIdentity.identityId, displayName: adminIdentity.displayName,
    status: "authenticated", csrf, expiresAt: Date.now() + 60_000,
  };
  if (sessionVersion !== null) session.sessionVersion = sessionVersion;
  if (centralSession) session.centralSession = centralSession;
  return `${OIDC_SESSION_COOKIE}=${seal(session, oidcConfig.sessionSecret, "oidc-session")}`;
}

function linkRequiredCookie(sessionVersion = 2) {
  const session = {
    sessionVersion,
    issuer: "https://login.infomaniak.com",
    subject: "candidate-provider-subject",
    displayName: "Personne candidate",
    status: "link_required",
    requestId: randomUUID(),
    requestExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    expiresAt: Date.now() + 60_000,
  };
  return `${OIDC_SESSION_COOKIE}=${seal(session, oidcConfig.sessionSecret, "oidc-session")}`;
}

const tasksWriterCatalog = {
  application_id: "n09-suivi-taches", catalog_version: 1,
  permissions: [
    { permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tâches du site.", status: "active" },
    { permission_id: "tasks:write", display_name: "Écrire", description: "Modifier les tâches du site.", status: "active" },
  ],
  scope_types: [
    { scope_type_id: "site", display_name: "Site", description: "Périmètre métier local.", status: "active" },
  ],
  roles: [
    { role_id: "tasks-writer", display_name: "Contributeur", description: "Lecture et écriture sur un site.", status: "active", permissions: ["tasks:read", "tasks:write"], scope_types: ["site"] },
  ],
  provisioning: {
    mode: "preexisting_profile_required", identity_key: "identity_id",
    readiness: "application_confirmation_required", automatic_profile_creation: false,
    email_matching: "forbidden",
    requirements: [
      { requirement_id: "application-user-profile", display_name: "Profil local", description: "Profil relié par identity_id." },
      { requirement_id: "site-membership", display_name: "Site local", description: "Périmètre confirmé par l’application." },
    ],
  },
};

async function seedRequestableTasks(repository) {
  repository.saveApplication({
    applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches",
    status: "active", registrationPolicy: "approval",
  }, adminAudit("application.registered", { applicationId: "n09-suivi-taches" }));
  const result = await publishApplicationAccessCatalog({
    repository,
    principal: {
      applicationId: "n09-suivi-taches", audience: "n09-suivi-taches",
      correlationId: randomUUID(),
    },
    payload: tasksWriterCatalog,
    source: "http-tests",
  });
  assert.equal(result.status, 201);
}

test("reçoit une demande publique uniquement depuis le portail autorisé", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessDecision: true });
  await seedRequestableTasks(adminRepository);
  await withServer({
    repository: adminRepository, portalOrigins: ["https://nsktech.fr"],
  }, async (baseUrl) => {
    const foreign = await fetch(`${baseUrl}/portal/access-requests`, {
      method: "POST", headers: { origin: "https://example.test", "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(foreign.status, 403);

    const response = await fetch(`${baseUrl}/portal/access-requests`, {
      method: "POST", headers: { origin: "https://nsktech.fr", "content-type": "application/json" },
      body: JSON.stringify({
        displayName: "Personne candidate", email: "candidate@example.test",
        applicationIds: ["n09-suivi-taches"],
        reason: "Accéder au suivi partagé pour les besoins de l’équipe.",
      }),
    });
    const body = await response.json();
    assert.equal(response.status, 202);
    assert.equal(response.headers.get("access-control-allow-origin"), "https://nsktech.fr");
    assert.equal(body.accepted, true);
    assert.match(body.request_id, /^[0-9a-f-]{36}$/);
    assert.equal(adminRepository.listAccessRequests("pending").length, 1);
  });
});

test("présente la demande seulement au responsable des décisions d’accès", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessDecision: true });
  await seedRequestableTasks(adminRepository);
  await withServer({
    repository: adminRepository, oidcConfig, portalOrigins: ["https://nsktech.fr"],
  }, async (baseUrl) => {
    await fetch(`${baseUrl}/portal/access-requests`, {
      method: "POST", headers: { origin: "https://nsktech.fr", "content-type": "application/json" },
      body: JSON.stringify({
        displayName: "Personne candidate", email: "candidate@example.test",
        applicationIds: ["n09-suivi-taches"],
        reason: "Accéder au suivi partagé pour les besoins de l’équipe.",
      }),
    });
    const response = await fetch(`${baseUrl}/admin/access-requests`, {
      headers: { cookie: adminCookie() },
    });
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Demandes d’accès/);
    assert.match(body, /Personne candidate/);
    assert.match(body, /candidate@example\.test/);
    assert.match(body, /Approuver comme Contributeur/);
    assert.match(body, /Refuser cette application/);
  });
});

test("expose une santé versionnée sans information interne", async () => {
  const release = {
    commit: "0123456789abcdef0123456789abcdef01234567",
    builtAt: "2026-08-18T12:00:00Z",
    environment: "production",
  };
  await withServer({ release }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok", release });
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("permissions-policy"), "camera=(), microphone=(), geolocation=(), payment=()");
  });
});

test("applique le socle visuel et de navigation obligatoire de NSK Tech 09", async () => {
  await withServer({}, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/`);
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(html, /Manrope-VariableFont_wght\.ttf/);
    assert.match(html, /nsktech09-logo-master\.png/);
    assert.match(html, /Ouvrir le portail NSK Tech 09 dans un nouvel onglet/);
    assert.match(html, /aria-label="Accès rapide"/);
    assert.match(html, /Choisir le thème/);
    assert.match(html, /N09 – Administration · version 0\.2\.7 · application web installable/);
    assert.match(html, /Mentions légales/);
    assert.match(html, /Confidentialité/);
    assert.match(html, /Comprendre\. Concevoir\. Transmettre\./);
    assert.match(response.headers.get("content-security-policy"), /script-src 'self'/);

    const logo = await fetch(`${baseUrl}/assets/nsktech09-logo-master.png`);
    assert.equal(logo.status, 200);
    assert.equal(logo.headers.get("content-type"), "image/png");
    assert.ok((await logo.arrayBuffer()).byteLength > 100_000);
  });
});

test("protège la console d’exploitation par une permission dédiée", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessRead: true });
  adminRepository.getNotificationOperationsSnapshot = async () => { throw new Error("must not be read"); };
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/notification-operations`, {
      headers: { cookie: adminCookie() },
    });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /permission dédiée à l’exploitation des notifications/);
  });
});

test("présente la file et les suppressions sans coordonnée personnelle ni action", async () => {
  const { adminRepository } = seededAdminRepository({ withNotificationOperations: true });
  adminRepository.getNotificationOperationsSnapshot = async () => ({
    events: {
      total: 2, pending: 0, processing: 0, retrying: 0, processed: 2, quarantined: 0,
      oldestAvailableAt: null, lastReceivedAt: "2026-08-12T10:00:00.000Z",
      lastProcessedAt: "2026-08-12T10:02:00.000Z",
    },
    notifications: { total: 0, unread: 0, archived: 0 },
    externalDeliveries: {
      total: 0, blocked: 0, nonBlocked: 0, pending: 0, processing: 0,
      retrying: 0, delivered: 0, quarantined: 0,
    },
    suppressions: { ownAction: 2, preferences: 0, unlinkedIdentity: 0 },
    processor: {
      status: "succeeded", lastStartedAt: "2026-08-12T10:01:59.000Z",
      lastFinishedAt: "2026-08-12T10:02:00.000Z", errorCode: null,
      claimed: 2, processed: 2, retried: 0, quarantined: 0, version: 4,
    },
    recentResolutions: [{
      sourceApplicationId: "n09-suivi-taches", eventId: "event_reference_1",
      policyVersion: "tasks-notification-policy-v1",
      suppressed: { own_action: 1, preferences: 0, unlinked_identity: 0 },
      internalNotificationCount: 0, blockedExternalDeliveryCount: 0,
      resolvedAt: "2026-08-12T10:02:00.000Z",
    }],
  });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/notification-operations`, {
      headers: { cookie: adminCookie() },
    });
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Exploitation des notifications/);
    assert.match(body, /action propre 2/);
    assert.match(body, /Tous bloqués/);
    assert.match(body, /Dernier cycle réussi/);
    assert.match(body, /pris 2 · traités 2 · repris 0 · quarantaines 0/);
    assert.doesNotMatch(body, /admin@example\.test|candidate@example\.test|password|secret/i);
    assert.doesNotMatch(body, /method="post" action="\/admin\/notification-operations/);
  });
});

test("présente le sélecteur central et conserve le parcours Infomaniak sécurisé", async () => {
  await withServer({ oidcConfig }, async (baseUrl) => {
    const home = await fetch(`${baseUrl}/`);
    assert.equal(home.status, 200);
    assert.match(await home.text(), /Choisir une méthode de connexion/);
    assert.match(home.headers.get("content-security-policy"), /default-src 'none'/);

    const selector = await fetch(`${baseUrl}/auth/login?return_to=%2F`);
    assert.equal(selector.status, 200);
    assert.match(await selector.text(), /Continuer avec Infomaniak/);

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

test("refuse un ancien cookie non versionné sans consulter le registre central", async () => {
  let assessments = 0;
  const administrationSessionAuthority = {
    mode: "enforce",
    assess: async () => { assessments += 1; return { allowed: true, reasonCode: "session_active" }; },
  };
  await withServer({ oidcConfig, administrationSessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`, {
      headers: { cookie: adminCookie("csrf-value", null, null) },
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { authenticated: false });
  });
  assert.equal(assessments, 0);
});

test("observe la session centrale sans rendre son résultat opposable", async () => {
  const centralSession = {
    sessionId: "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702",
    secret: "B".repeat(43),
  };
  const observations = [];
  const administrationSessionAuthority = {
    mode: "observe",
    issue: async () => null,
    observe: async (input) => {
      observations.push(input);
      throw new Error("simulated central divergence");
    },
  };
  await withServer({ oidcConfig, administrationSessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`, {
      headers: { cookie: adminCookie("csrf-value", centralSession) },
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).authenticated, true);
    await new Promise((resolve) => setImmediate(resolve));
  });
  assert.deepEqual(observations, [{ credential: centralSession, identityId: adminIdentity.identityId }]);
});

test("ferme l'accès HTTP lorsque la session Administration centrale est refusée", async () => {
  const credential = {
    sessionId: "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702",
    secret: "B".repeat(43),
  };
  const assessments = [];
  const administrationSessionAuthority = {
    mode: "enforce",
    assess: async (input) => {
      assessments.push(input);
      return { allowed: false, reasonCode: "session_revoked" };
    },
  };
  await withServer({ oidcConfig, administrationSessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`, {
      headers: { cookie: adminCookie("csrf-value", credential) },
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { authenticated: false });
  });
  assert.deepEqual(assessments, [{ credential, identityId: adminIdentity.identityId }]);
});

test("confirme la déconnexion seulement après révocation centrale", async () => {
  const credential = {
    sessionId: "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702",
    secret: "B".repeat(43),
  };
  const revocations = [];
  const authority = (revoked) => ({
    mode: "enforce",
    revokeCurrent: async (input) => {
      revocations.push(input);
      return revoked
        ? { revoked: true, reasonCode: "session_revoked" }
        : { revoked: false, reasonCode: "session_registry_unavailable" };
    },
  });
  await withServer({ oidcConfig, administrationSessionAuthority: authority(true) }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/logout`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: adminCookie("csrf-value", credential) },
    });
    assert.equal(response.status, 303);
    assert.match(response.headers.get("set-cookie"), /Max-Age=0/);
  });
  await withServer({ oidcConfig, administrationSessionAuthority: authority(false) }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/logout`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: adminCookie("csrf-value", credential) },
    });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("set-cookie"), null);
    assert.match(await response.text(), /Aucun succès fictif/);
  });
  assert.equal(revocations.length, 2);
  assert.deepEqual(revocations[0], { credential, identityId: adminIdentity.identityId });
});

test("ferme localement une session en attente de rattachement sans révocation centrale fictive", async () => {
  let revocations = 0;
  const administrationSessionAuthority = {
    mode: "enforce",
    revokeCurrent: async () => {
      revocations += 1;
      return { revoked: false, reasonCode: "session_registry_unavailable" };
    },
  };
  await withServer({ oidcConfig, administrationSessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/logout`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: linkRequiredCookie() },
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/");
    assert.match(response.headers.get("set-cookie"), /Max-Age=0/);
  });
  assert.equal(revocations, 0);
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
  const publication = await publishAdministrationAccessCatalog(adminRepository, {
    database: "n09_admin_preprod", allowBootstrap: "true",
  });
  assert.equal(publication.created, true);
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access`, { headers: { cookie: adminCookie() } });
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.match(body, /Utilisateurs et accès/);
    assert.match(body, /Admin NSK/);
    assert.match(body, /N09 – Administration/);
    assert.match(body, /Catalogue v7/);
    assert.match(body, /Responsable des rattachements/);
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
    assert.match(body, /Décider les accès/);
    assert.match(body, new RegExp(assignmentId));
    assert.match(body, /Accorder un accès gouverné/);
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

test("accorde depuis l’interface uniquement un rôle actif du catalogue publié", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessDecision: true });
  adminRepository.saveApplication({
    applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches",
    status: "active", registrationPolicy: "closed",
  }, adminAudit("application.registered", { applicationId: "n09-suivi-taches" }));
  const publication = await publishApplicationAccessCatalog({
    repository: adminRepository,
    principal: { applicationId: "n09-suivi-taches", audience: "n09-suivi-taches" },
    payload: tasksWriterCatalog,
  });
  assert.equal(publication.status, 201);

  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const page = await fetch(`${baseUrl}/admin/access-decisions`, { headers: { cookie: adminCookie() } });
    const body = await page.text();
    assert.equal(page.status, 200);
    assert.match(body, /N09 – Suivi des tâches — Contributeur/);
    assert.match(body, /Activation conditionnelle/);
    assert.match(body, /application-user-profile/);

    const forged = await fetch(`${baseUrl}/admin/access-decisions/grant`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie("expected-csrf"), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({
        csrf: "forged-csrf", identity_id: targetIdentity.identityId,
        application_id: "n09-suivi-taches", catalog_version: "1", role_id: "tasks-writer",
        scope_type: "site", scope_id: "site_09",
        justification: "Contribution nécessaire sur le site pilote validé",
      }),
    });
    assert.equal(forged.status, 403);
    assert.equal(adminRepository.listAssignments(targetIdentity.identityId, "n09-suivi-taches").length, 0);

    const auditBefore = adminRepository.auditCount();
    const response = await fetch(`${baseUrl}/admin/access-decisions/grant`, {
      method: "POST", redirect: "manual", headers: {
        cookie: adminCookie(), "content-type": "application/x-www-form-urlencoded",
      }, body: new URLSearchParams({
        csrf: "csrf-value", identity_id: targetIdentity.identityId,
        application_id: "n09-suivi-taches", catalog_version: "1", role_id: "tasks-writer",
        scope_type: "site", scope_id: "site_09",
        justification: "Contribution nécessaire sur le site pilote validé",
      }),
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/admin/access-decisions");
    assert.equal(adminRepository.auditCount(), auditBefore + 1);
  });
  const [granted] = adminRepository.listAssignments(targetIdentity.identityId, "n09-suivi-taches");
  assert.equal(granted.roleId, "tasks-writer");
  assert.deepEqual(granted.permissions, ["tasks:read", "tasks:write"]);
  assert.deepEqual(granted.conditions, ["application-user-profile", "site-membership"]);
  assert.equal(granted.scopeType, "site");
  assert.equal(granted.scopeId, "site_09");
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

test("inscrit une nouvelle session rattachée en observation dans le cookie chiffré", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  let expectedNonce;
  const fetchImpl = async (url) => {
    if (String(url).endsWith("/oauth2/jwks")) {
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "shadow-key", alg: "RS256" }] }), { status: 200 });
    }
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "shadow-key" })).toString("base64url");
    const claims = Buffer.from(JSON.stringify({
      iss: "https://login.infomaniak.com", aud: oidcConfig.clientId, sub: "linked-subject",
      nonce: expectedNonce, iat: now - 1, exp: now + 300,
    })).toString("base64url");
    const signature = sign("RSA-SHA256", Buffer.from(`${header}.${claims}`), privateKey).toString("base64url");
    return new Response(JSON.stringify({ id_token: `${header}.${claims}.${signature}` }), { status: 200 });
  };
  const { adminRepository } = seededAdminRepository();
  adminRepository.findExternalIdentity = async () => ({ identityId: adminIdentity.identityId, status: "active" });
  const centralSession = {
    sessionId: "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702",
    secret: "B".repeat(43),
  };
  const enrolled = [];
  const administrationSessionAuthority = {
    mode: "observe",
    issue: async (input) => { enrolled.push(input); return centralSession; },
    observe: async () => ({ outcome: "active" }),
  };
  await withServer({ repository: adminRepository, oidcConfig, fetchImpl, administrationSessionAuthority }, async (baseUrl) => {
    const start = await fetch(`${baseUrl}/auth/infomaniak/start`, { redirect: "manual" });
    const authorization = new URL(start.headers.get("location"));
    expectedNonce = authorization.searchParams.get("nonce");
    const transactionCookie = start.headers.get("set-cookie").split(";")[0];
    const callback = await fetch(`${baseUrl}/auth/infomaniak/callback?code=one-time-code&state=${authorization.searchParams.get("state")}`, {
      headers: { cookie: transactionCookie }, redirect: "manual",
    });
    assert.equal(callback.status, 303);
    const sealedSession = callback.headers.get("set-cookie").match(/n09_oidc_session=([^;,]+)/)?.[1];
    const session = open(sealedSession, oidcConfig.sessionSecret, "oidc-session");
    assert.equal(session.sessionVersion, 2);
    assert.deepEqual(session.centralSession, centralSession);
    assert.equal(session.identityId, adminIdentity.identityId);
  });
  assert.deepEqual(enrolled, [{ identityId: adminIdentity.identityId }]);
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

test("révoque une session uniquement pour l'application technique propriétaire", async () => {
  let revocation;
  const authenticate = async () => ({
    applicationId: "tasks", audience: "tasks", correlationId: "correlation-session-revoke",
  });
  const sessionAuthority = {
    revokeForApplication: async (request) => {
      revocation = request;
      return { revoked: true, reasonCode: "session_revoked" };
    },
  };
  await withServer({ authenticate, sessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/application-sessions/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        application_id: "tasks",
        identity_id: "identity-1",
        session_id: "session-1",
      }),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { revoked: true, reason_code: "session_revoked" });
  });
  assert.deepEqual(revocation, {
    applicationId: "tasks",
    identityId: "identity-1",
    sessionId: "session-1",
    reason: "Déconnexion demandée dans N09 – Suivi des tâches",
  });
});

test("ferme l'accès HTTP lorsque la session applicative centrale est révoquée", async () => {
  const authenticate = async () => ({
    applicationId: "tasks", audience: "tasks", correlationId: "correlation-session-denied",
  });
  const sessionAuthority = {
    assess: async () => ({ allowed: false, reasonCode: "session_revoked" }),
  };
  await withServer({ authenticate, sessionAuthority }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/access-decisions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...payload, session_id: "session-1", session_secret: "secret-1" }),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { allowed: false, reason_code: "session_revoked" });
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

test("reçoit un catalogue uniquement de l’application technique propriétaire", async () => {
  const catalogRepository = new TransactionalMemoryRepository();
  catalogRepository.saveApplication({
    applicationId: "tasks", displayName: "Tâches", status: "active", registrationPolicy: "closed",
  }, adminAudit("application.registered", { applicationId: "tasks" }));
  const catalogPayload = {
    application_id: "tasks", catalog_version: 1,
    permissions: [{ permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tâches.", status: "active" }],
    scope_types: [{ scope_type_id: "global", display_name: "Global", description: "Toute l’application.", status: "active" }],
    roles: [{ role_id: "tasks-reader", display_name: "Lecteur", description: "Lecture globale.", status: "active", permissions: ["tasks:read"], scope_types: ["global"] }],
    provisioning: {
      mode: "preexisting_profile_required", identity_key: "identity_id",
      readiness: "application_confirmation_required", automatic_profile_creation: false,
      email_matching: "forbidden",
      requirements: [{ requirement_id: "local-profile", display_name: "Profil local", description: "Profil confirmé par l’application." }],
    },
  };
  await withServer({
    repository: catalogRepository,
    authenticate: async () => ({ applicationId: "tasks", audience: "tasks" }),
  }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/application-access-catalogs`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(catalogPayload),
    });
    assert.equal(response.status, 201);
    assert.equal((await response.json()).created, true);
    assert.equal(catalogRepository.getLatestApplicationAccessCatalog("tasks").catalogVersion, 1);
  });
  await withServer({ repository: catalogRepository }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/internal/v1/application-access-catalogs`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(catalogPayload),
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "authentication_required" });
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
