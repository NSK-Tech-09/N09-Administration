import assert from "node:assert/strict";
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
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 â€“ Administration",
    status: "active", registrationPolicy: "closed",
  }, adminAudit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  if (withPermission) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "identity-link-administrator", permissions: [LINK_DECISION_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de lâ€™administration", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  if (withAccessRead) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-directory-reader", permissions: [ACCESS_DIRECTORY_READ_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de la consultation des accÃ¨s", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  if (withAccessDecision) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "access-decision-administrator", permissions: [ACCESS_DECISION_PERMISSION], scopeType: null,
      scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test des dÃ©cisions dâ€™accÃ¨s", decidedBy: adminIdentity.identityId,
      inheritedFromGroup: null, version: 1,
    }, adminAudit("assignment.created", { subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  }
  if (withNotificationOperations) {
    adminRepository.saveAssignment({
      assignmentId: randomUUID(), subjectId: adminIdentity.identityId, applicationId: ADMIN_APPLICATION_ID,
      roleId: "notification-operations-reader", permissions: [NOTIFICATION_OPERATIONS_READ_PERMISSION],
      scopeType: null, scopeId: null, conditions: [], status: "active", validFrom: null, validUntil: null,
      reason: "Test de lâ€™exploitation des notifications", decidedBy: adminIdentity.identityId,
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

function adminCookie(csrf = "csrf-value", shadowSession = null) {
  const session = {
    issuer: "https://login.infomaniak.com", subject: "admin-provider-subject",
    identityId: adminIdentity.identityId, displayName: adminIdentity.displayName,
    status: "authenticated", csrf, expiresAt: Date.now() + 60_000,
  };
  if (shadowSession) session.shadowSession = shadowSession;
  return `${OIDC_SESSION_COOKIE}=${seal(session, oidcConfig.sessionSecret, "oidc-session")}`;
}

const tasksWriterCatalog = {
  application_id: "n09-suivi-taches", catalog_version: 1,
  permissions: [
    { permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tÃ¢ches du site.", status: "active" },
    { permission_id: "tasks:write", display_name: "Ã‰crire", description: "Modifier les tÃ¢ches du site.", status: "active" },
  ],
  scope_types: [
    { scope_type_id: "site", display_name: "Site", description: "PÃ©rimÃ¨tre mÃ©tier local.", status: "active" },
  ],
  roles: [
    { role_id: "tasks-writer", display_name: "Contributeur", description: "Lecture et Ã©criture sur un site.", status: "active", permissions: ["tasks:read", "tasks:write"], scope_types: ["site"] },
  ],
  provisioning: {
    mode: "preexisting_profile_required", identity_key: "identity_id",
    readiness: "application_confirmation_required", automatic_profile_creation: false,
    email_matching: "forbidden",
    requirements: [
      { requirement_id: "application-user-profile", display_name: "Profil local", description: "Profil reliÃ© par identity_id." },
      { requirement_id: "site-membership", display_name: "Site local", description: "PÃ©rimÃ¨tre confirmÃ© par lâ€™application." },
    ],
  },
};

test("expose une santÃ© minimale sans information interne", async () => {
  await withServer({}, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
    assert.equal(response.headers.get("cache-control"), "no-store");
  });
});

test("protÃ¨ge la console dâ€™exploitation par une permission dÃ©diÃ©e", async () => {
  const { adminRepository } = seededAdminRepository({ withAccessRead: true });
  adminRepository.getNotificationOperationsSnapshot = async () => { throw new Error("must not be read"); };
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/notification-operations`, {
      headers: { cookie: adminCookie() },
    });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /permission dÃ©diÃ©e Ã  lâ€™exploitation des notifications/);
  });
});

test("prÃ©sente la file et les suppressions sans coordonnÃ©e personnelle ni action", async () => {
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
    assert.match(body, /Tous bloquÃ©s/);
    assert.match(body, /Dernier cycle rÃ©ussi/);
    assert.match(body, /pris 2 Â· traitÃ©s 2 Â· repris 0 Â· quarantaines 0/);
    assert.doesNotMatch(body, /admin@example\.test|candidate@example\.test|password|secret/i);
    assert.doesNotMatch(body, /method="post" action="\/admin\/notification-operations/);
  });
});

test("prÃ©sente le portail et dÃ©marre le parcours Infomaniak sÃ©curisÃ©", async () => {
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

test("ne rÃ©vÃ¨le pas la preuve externe dans l'Ã©tat de session public", async () => {
  await withServer({ oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { authenticated: false });
  });
});

test("observe la session centrale sans rendre son rÃ©sultat opposable", async () => {
  const shadowSession = {
    sessionId: "b14ad8d3-b14b-4f2e-8f0b-c79dfc1fd702",
    secret: "B".repeat(43),
  };
  const observations = [];
  const sessionShadow = {
    enroll: async () => null,
    observe: async (input) => {
      observations.push(input);
      throw new Error("simulated central divergence");
    },
  };
  await withServer({ oidcConfig, sessionShadow }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/session`, {
      headers: { cookie: adminCookie("csrf-value", shadowSession) },
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).authenticated, true);
    await new Promise((resolve) => setImmediate(resolve));
  });
  assert.deepEqual(observations, [{ credential: shadowSession, identityId: adminIdentity.identityId }]);
});

test("refuse lâ€™administration Ã  une identitÃ© rattachÃ©e sans permission dÃ©diÃ©e", async () => {
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

test("sÃ©pare la consultation des accÃ¨s du pouvoir de dÃ©cision sur les rattachements", async () => {
  const { adminRepository } = seededAdminRepository({ withPermission: true, withAccessRead: false });
  await withServer({ repository: adminRepository, oidcConfig }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/admin/access`, { headers: { cookie: adminCookie() } });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /permission dÃ©diÃ©e Ã  la consultation des accÃ¨s/);
 ß¾z¶‰žËkºwµçMÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹•Ñ1¥¹­I•ÅÕ•ÍÐ¡±¥¹­I•ÅÕ•ÍÐ¹É•ÅÕ•ÍÑ%¤¹ÍÑ…ÑÕÌ°€‰…ÁÁÉ½Ù•ˆ¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹±¥ÍÑÍÍ¥¹µ•¹ÑÌ¡Ñ…É•Ñ%‘•¹Ñ¥Ñä¹¥‘•¹Ñ¥Ñå%°5%9}AA1%Q%=9}%¤¹±•¹Ñ °€À¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹…Õ‘¥Ñ½Õ¹Ð ¤°…Õ‘¥Ñ	•™½É”€¬€Ä¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹Ù•É¥™åÕ‘¥Ñ¡…¥¸ ¤°ÑÉÕ”¤ì)ô¤ì()Ñ•ÍÐ ‰É•™ÕÍ”Õ¹”‘•µ…¹‘”…Ù•Œ©ÕÍÑ¥™¥…Ñ¥½¸•ÐÑÉ…”±„“¥¥Í¥½¸ˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐì…‘µ¥¹I•Á½Í¥Ñ½Éä°±¥¹­I•ÅÕ•ÍÐô€ôÍ••‘•‘‘µ¥¹I•Á½Í¥Ñ½Éä ¤ì(€½¹ÍÐ…Õ‘¥Ñ	•™½É”€ô…‘µ¥¹I•Á½Í¥Ñ½Éä¹…Õ‘¥Ñ½Õ¹Ð ¤ì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ìÉ•Á½Í¥Ñ½Éäè…‘µ¥¹I•Á½Í¥Ñ½Éä°½¥‘½¹™¥œô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…‘µ¥¸½±¥¹¬µÉ•ÅÕ•ÍÑÌ¼‘í±¥¹­I•ÅÕ•ÍÐ¹É•ÅÕ•ÍÑ%‘ô½É•©•Ñ€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°É•‘¥É•Ðè€‰µ…¹Õ…°ˆ°¡•…‘•ÉÌèì(€€€€€€€½½­¥”è…‘µ¥¹½½­¥” ¤°€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½àµÝÝÜµ™½É´µÕÉ±•¹½‘•ˆ°(€€€€€ô°‰½‘äè¹•ÜUI1M•…É¡A…É…µÌ¡ìÍÉ˜è€‰ÍÉ˜µÙ…±Õ”ˆ°©ÕÍÑ¥™¥…Ñ¥½¸è€‰AÉ•ÕÙ”¥¹ÍÕ™™¥Í…¹Ñ”ˆô¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÌÀÌ¤ì(€ô¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹•Ñ1¥¹­I•ÅÕ•ÍÐ¡±¥¹­I•ÅÕ•ÍÐ¹É•ÅÕ•ÍÑ%¤¹ÍÑ…ÑÕÌ°€‰É•©•Ñ•ˆ¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹…Õ‘¥Ñ½Õ¹Ð ¤°…Õ‘¥Ñ	•™½É”€¬€Ä¤ì(€…ÍÍ•ÉÐ¹•ÅÕ…°¡…‘µ¥¹I•Á½Í¥Ñ½Éä¹Ù•É¥™åÕ‘¥Ñ¡…¥¸ ¤°ÑÉÕ”¤ì)ô¤ì()Ñ•ÍÐ ‰¸•áÁ½Í”Õ¸½‘”=%ÏíÈÅÕ”±½ÉÍÅÕ”±”‰…¹Œ‘”Ù…±¥‘…Ñ¥½¸°…ÕÑ½É¥Í”ˆ°…Íå¹Œ€ ¤€ôøì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì½¥‘½¹™¥œèì€¸¸¹½¥‘½¹™¥œ°•áÁ½Í•M…™•ÉÉ½ÉÌèÑÉÕ”ôô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…ÕÑ ½¥¹™½µ…¹¥…¬½…±±‰…­€¤ì(€€€½¹ÍÐ‰½‘ä€ô…Ý…¥ÐÉ•ÍÁ½¹Í”¹Ñ•áÐ ¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÐÀÀ¤ì(€€€…ÍÍ•ÉÐ¹µ…Ñ ¡‰½‘ä°€½¥¹½µÁ±•Ñ•}½¥‘}…±±‰…¬¼¤ì(€€€…ÍÍ•ÉÐ¹‘½•Í9½Ñ5…Ñ ¡‰½‘ä°€½±¥•¹ÐµÍ•É•ÑñÍ•ÍÍ¥½¸µÍ•É•Ð¼¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰Ù…±¥‘”±”É•Ñ½ÕÈ%¹™½µ…¹¥…¬•ÐË¥”Í•Õ±•µ•¹ÐÕ¹”Í•ÍÍ¥½¸ƒ€É…ÑÑ…¡•Èˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐìÁÕ‰±¥-•ä°ÁÉ¥Ù…Ñ•-•äô€ô•¹•É…Ñ•-•åA…¥ÉMå¹Œ ‰ÉÍ„ˆ°ìµ½‘Õ±ÕÍ1•¹Ñ è€ÈÀÐàô¤ì(€½¹ÍÐ©Ý¬€ôÁÕ‰±¥-•ä¹•áÁ½ÉÐ¡ì™½Éµ…Ðè€‰©Ý¬ˆô¤ì(€±•Ð•áÁ•Ñ•‘9½¹”ì(€½¹ÍÐ™•Ñ¡%µÁ°€ô…Íå¹Œ€¡ÕÉ°¤€ôøì(€€€¥˜€¡MÑÉ¥¹œ¡ÕÉ°¤¹•¹‘Í]¥Ñ  ˆ½½…ÕÑ È½©Ý­Ìˆ¤¤ì(€€€€€É•ÑÕÉ¸¹•ÜI•ÍÁ½¹Í”¡)M=8¹ÍÑÉ¥¹¥™ä¡ì­•åÌèmì€¸¸¹©Ý¬°­¥è€‰Ñ•ÍÐµ­•äˆ°…±œè€‰ILÈÔØˆõtô¤°ìÍÑ…ÑÕÌè€ÈÀÀô¤ì(€€€ô(€€€½¹ÍÐ¹½Ü€ô5…Ñ ¹™±½½È¡…Ñ”¹¹½Ü ¤€¼€ÄÀÀÀ¤ì(€€€½¹ÍÐ¡•…‘•È€ô	Õ™™•È¹™É½´¡)M=8¹ÍÑÉ¥¹¥™ä¡ì…±œè€‰ILÈÔØˆ°­¥è€‰Ñ•ÍÐµ­•äˆô¤¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€½¹ÍÐ±…¥µÌ€ô	Õ™™•È¹™É½´¡)M=8¹ÍÑÉ¥¹¥™ä¡ì(€€€€€¥ÍÌè€‰¡ÑÑÁÌè¼½±½¥¸¹¥¹™½µ…¹¥…¬¹½´ˆ°…Õè½¥‘½¹™¥œ¹±¥•¹Ñ%°ÍÕˆè€‰•áÑ•É¹…°´ÐÈˆ°(€€€€€¹…µ”è€‰A•ÉÍ½¹¹”‘”Ñ•ÍÐˆ°¹½¹”è•áÁ•Ñ•‘9½¹”°¥…Ðè¹½Ü€´€Ä°•áÀè¹½Ü€¬€ÌÀÀ°(€€€ô¤¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€½¹ÍÐÍ¥¹…ÑÕÉ”€ôÍ¥¸ ‰IMµM!ÈÔØˆ°	Õ™™•È¹™É½´¡€‘í¡•…‘•Éô¸‘í±…¥µÍõ€¤°ÁÉ¥Ù…Ñ•-•ä¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€É•ÑÕÉ¸¹•ÜI•ÍÁ½¹Í”¡)M=8¹ÍÑÉ¥¹¥™ä¡ì¥‘}Ñ½­•¸è€‘í¡•…‘•Éô¸‘í±…¥µÍô¸‘íÍ¥¹…ÑÕÉ•õ€ô¤°ìÍÑ…ÑÕÌè€ÈÀÀô¤ì(€ôì(€½¹ÍÐÍ…Ù•‘I•ÅÕ•ÍÑÌ€ômtì(€½¹ÍÐ±¥¹­I•Á½Í¥Ñ½Éä€ôì(€€€€¸¸¹É•Á½Í¥Ñ½Éä°(€€€™¥¹‘áÑ•É¹…±%‘•¹Ñ¥Ñäè…Íå¹Œ€ ¤€ôø¹Õ±°°(€€€™¥¹‘Ñ¥Ù•1¥¹­I•ÅÕ•ÍÐè…Íå¹Œ€ ¤€ôø¹Õ±°°(€€€Í…Ù•1¥¹­I•ÅÕ•ÍÐè…Íå¹Œ€¡É•ÅÕ•ÍÐ¤€ôøÍ…Ù•‘I•ÅÕ•ÍÑÌ¹ÁÕÍ ¡É•ÅÕ•ÍÐ¤°(€ôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ìÉ•Á½Í¥Ñ½Éäè±¥¹­I•Á½Í¥Ñ½Éä°½¥‘½¹™¥œ°™•Ñ¡%µÁ°ô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÍÑ…ÉÐ€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…ÕÑ ½¥¹™½µ…¹¥…¬½ÍÑ…ÉÑ€°ìÉ•‘¥É•Ðè€‰µ…¹Õ…°ˆô¤ì(€€€½¹ÍÐ…ÕÑ¡½É¥é…Ñ¥½¸€ô¹•ÜUI0¡ÍÑ…ÉÐ¹¡•…‘•ÉÌ¹•Ð ‰±½…Ñ¥½¸ˆ¤¤ì(€€€•áÁ•Ñ•‘9½¹”€ô…ÕÑ¡½É¥é…Ñ¥½¸¹Í•…É¡A…É…µÌ¹•Ð ‰¹½¹”ˆ¤ì(€€€½¹ÍÐÑÉ…¹Í…Ñ¥½¹½½­¥”€ôÍÑ…ÉÐ¹¡•…‘•ÉÌ¹•Ð ‰Í•Ðµ½½­¥”ˆ¤¹ÍÁ±¥Ð ˆìˆ¥lÁtì(€€€½¹ÍÐ…±±‰…¬€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…ÕÑ ½¥¹™½µ…¹¥…¬½…±±‰…¬ý½‘”õ½¹”µÑ¥µ”µ½‘”™ÍÑ…Ñ”ô‘í…ÕÑ¡½É¥é…Ñ¥½¸¹Í•…É¡A…É…µÌ¹•Ð ‰ÍÑ…Ñ”ˆ¥õ€°ì(€€€€€¡•…‘•ÉÌèì½½­¥”èÑÉ…¹Í…Ñ¥½¹½½­¥”ô°É•‘¥É•Ðè€‰µ…¹Õ…°ˆ°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡…±±‰…¬¹ÍÑ…ÑÕÌ°€ÌÀÌ¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡…±±‰…¬¹¡•…‘•ÉÌ¹•Ð ‰±½…Ñ¥½¸ˆ¤°€ˆ¼ˆ¤ì(€€€½¹ÍÐÍ•Ñ½½­¥”€ô…±±‰…¬¹¡•…‘•ÉÌ¹•Ð ‰Í•Ðµ½½­¥”ˆ¤ì(€€€…ÍÍ•ÉÐ¹µ…Ñ ¡Í•Ñ½½­¥”°€½¸Àå}½¥‘}ÑÉ…¹Í…Ñ¥½¸ôì¼¤ì(€€€…ÍÍ•ÉÐ¹µ…Ñ ¡Í•Ñ½½­¥”°€½¸Àå}½¥‘}Í•ÍÍ¥½¸ô¼¤ì(€€€…ÍÍ•ÉÐ¹‘½•Í9½Ñ5…Ñ ¡Í•Ñ½½­¥”°€½•áÑ•É¹…°´ÐÉñA•ÉÍ½¹¹”‘”Ñ•ÍÐ¼¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡Í…Ù•‘I•ÅÕ•ÍÑÌ¹±•¹Ñ °€Ä¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡Í…Ù•‘I•ÅÕ•ÍÑÍlÁt¹ÍÑ…ÑÕÌ°€‰Á•¹‘¥¹œˆ¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡Í…Ù•‘I•ÅÕ•ÍÑÍlÁt¹ÍÕ‰©•Ð°€‰•áÑ•É¹…°´ÐÈˆ¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰¥¹ÍÉ¥ÐÕ¹”¹½ÕÙ•±±”Í•ÍÍ¥½¸É…ÑÑ…£¥”•¸½‰Í•ÉÙ…Ñ¥½¸‘…¹Ì±”½½­¥”¡¥™™Ë¤ˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐìÁÕ‰±¥-•ä°ÁÉ¥Ù…Ñ•-•äô€ô•¹•É…Ñ•-•åA…¥ÉMå¹Œ ‰ÉÍ„ˆ°ìµ½‘Õ±ÕÍ1•¹Ñ è€ÈÀÐàô¤ì(€½¹ÍÐ©Ý¬€ôÁÕ‰±¥-•ä¹•áÁ½ÉÐ¡ì™½Éµ…Ðè€‰©Ý¬ˆô¤ì(€±•Ð•áÁ•Ñ•‘9½¹”ì(€½¹ÍÐ™•Ñ¡%µÁ°€ô…Íå¹Œ€¡ÕÉ°¤€ôøì(€€€¥˜€¡MÑÉ¥¹œ¡ÕÉ°¤¹•¹‘Í]¥Ñ  ˆ½½…ÕÑ È½©Ý­Ìˆ¤¤ì(€€€€€É•ÑÕÉ¸¹•ÜI•ÍÁ½¹Í”¡)M=8¹ÍÑÉ¥¹¥™ä¡ì­•åÌèmì€¸¸¹©Ý¬°­¥è€‰Í¡…‘½Üµ­•äˆ°…±œè€‰ILÈÔØˆõtô¤°ìÍÑ…ÑÕÌè€ÈÀÀô¤ì(€€€ô(€€€½¹ÍÐ¹½Ü€ô5…Ñ ¹™±½½È¡…Ñ”¹¹½Ü ¤€¼€ÄÀÀÀ¤ì(€€€½¹ÍÐ¡•…‘•È€ô	Õ™™•È¹™É½´¡)M=8¹ÍÑÉ¥¹¥™ä¡ì…±œè€‰ILÈÔØˆ°­¥è€‰Í¡…‘½Üµ­•äˆô¤¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€½¹ÍÐ±…¥µÌ€ô	Õ™™•È¹™É½´¡)M=8¹ÍÑÉ¥¹¥™ä¡ì(€€€€€¥ÍÌè€‰¡ÑÑÁÌè¼½±½¥¸¹¥¹™½µ…¹¥…¬¹½´ˆ°…Õè½¥‘½¹™¥œ¹±¥•¹Ñ%°ÍÕˆè€‰±¥¹­•µÍÕ‰©•Ðˆ°(€€€€€¹½¹”è•áÁ•Ñ•‘9½¹”°¥…Ðè¹½Ü€´€Ä°•áÀè¹½Ü€¬€ÌÀÀ°(€€€ô¤¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€½¹ÍÐÍ¥¹…ÑÕÉ”€ôÍ¥¸ ‰IMµM!ÈÔØˆ°	Õ™™•È¹™É½´¡€‘í¡•…‘•Éô¸‘í±…¥µÍõ€¤°ÁÉ¥Ù…Ñ•-•ä¤¹Ñ½MÑÉ¥¹œ ‰‰…Í”ØÑÕÉ°ˆ¤ì(€€€É•ÑÕÉ¸¹•ÜI•ÍÁ½¹Í”¡)M=8¹ÍÑÉ¥¹¥™ä¡ì¥‘}Ñ½­•¸è€‘í¡•…‘•Éô¸‘í±…¥µÍô¸‘íÍ¥¹…ÑÕÉ•õ€ô¤°ìÍÑ…ÑÕÌè€ÈÀÀô¤ì(€ôì(€½¹ÍÐì…‘µ¥¹I•Á½Í¥Ñ½Éäô€ôÍ••‘•‘‘µ¥¹I•Á½Í¥Ñ½Éä ¤ì(€…‘µ¥¹I•Á½Í¥Ñ½Éä¹™¥¹‘áÑ•É¹…±%‘•¹Ñ¥Ñä€ô…Íå¹Œ€ ¤€ôø€¡ì¥‘•¹Ñ¥Ñå%è…‘µ¥¹%‘•¹Ñ¥Ñä¹¥‘•¹Ñ¥Ñå%°ÍÑ…ÑÕÌè€‰…Ñ¥Ù”ˆô¤ì(€½¹ÍÐÍ¡…‘½ÝM•ÍÍ¥½¸€ôì(€€€Í•ÍÍ¥½¹%è€‰ˆÄÑ…áÌµˆÄÑˆ´Ñ˜É”´á˜ÁˆµŒÜå‘™ŒÅ™ÜÀÈˆ°(€€€Í•É•Ðè€‰ˆ¹É•Á•…Ð ÐÌ¤°(€ôì(€½¹ÍÐ•¹É½±±•€ômtì(€½¹ÍÐÍ•ÍÍ¥½¹M¡…‘½Ü€ôì(€€€•¹É½±°è…Íå¹Œ€¡¥¹ÁÕÐ¤€ôøì•¹É½±±•¹ÁÕÍ ¡¥¹ÁÕÐ¤ìÉ•ÑÕÉ¸Í¡…‘½ÝM•ÍÍ¥½¸ìô°(€€€½‰Í•ÉÙ”è…Íå¹Œ€ ¤€ôø€¡ì½ÕÑ½µ”è€‰…Ñ¥Ù”ˆô¤°(€ôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ìÉ•Á½Í¥Ñ½Éäè…‘µ¥¹I•Á½Í¥Ñ½Éä°½¥‘½¹™¥œ°™•Ñ¡%µÁ°°Í•ÍÍ¥½¹M¡…‘½Üô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÍÑ…ÉÐ€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…ÕÑ ½¥¹™½µ…¹¥…¬½ÍÑ…ÉÑ€°ìÉ•‘¥É•Ðè€‰µ…¹Õ…°ˆô¤ì(€€€½¹ÍÐ…ÕÑ¡½É¥é…Ñ¥½¸€ô¹•ÜUI0¡ÍÑ…ÉÐ¹¡•…‘•ÉÌ¹•Ð ‰±½…Ñ¥½¸ˆ¤¤ì(€€€•áÁ•Ñ•‘9½¹”€ô…ÕÑ¡½É¥é…Ñ¥½¸¹Í•…É¡A…É…µÌ¹•Ð ‰¹½¹”ˆ¤ì(€€€½¹ÍÐÑÉ…¹Í…Ñ¥½¹½½­¥”€ôÍÑ…ÉÐ¹¡•…‘•ÉÌ¹•Ð ‰Í•Ðµ½½­¥”ˆ¤¹ÍÁ±¥Ð ˆìˆ¥lÁtì(€€€½¹ÍÐ…±±‰…¬€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½…ÕÑ ½¥¹™½µ…¹¥…¬½…±±‰…¬ý½‘”õ½¹”µÑ¥µ”µ½‘”™ÍÑ…Ñ”ô‘í…ÕÑ¡½É¥é…Ñ¥½¸¹Í•…É¡A…É…µÌ¹•Ð ‰ÍÑ…Ñ”ˆ¥õ€°ì(€€€€€¡•…‘•ÉÌèì½½­¥”èÑÉ…¹Í…Ñ¥½¹½½­¥”ô°É•‘¥É•Ðè€‰µ…¹Õ…°ˆ°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡…±±‰…¬¹ÍÑ…ÑÕÌ°€ÌÀÌ¤ì(€€€½¹ÍÐÍ•…±•‘M•ÍÍ¥½¸€ô…±±‰…¬¹¡•…‘•ÉÌ¹•Ð ‰Í•Ðµ½½­¥”ˆ¤¹µ…Ñ  ½¸Àå}½¥‘}Í•ÍÍ¥½¸ô¡mxì±t¬¤¼¤ü¹lÅtì(€€€½¹ÍÐÍ•ÍÍ¥½¸€ô½Á•¸¡Í•…±•‘M•ÍÍ¥½¸°½¥‘½¹™¥œ¹Í•ÍÍ¥½¹M•É•Ð°€‰½¥‘ŒµÍ•ÍÍ¥½¸ˆ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡Í•ÍÍ¥½¸¹Í¡…‘½ÝM•ÍÍ¥½¸°Í¡…‘½ÝM•ÍÍ¥½¸¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡Í•ÍÍ¥½¸¹¥‘•¹Ñ¥Ñå%°…‘µ¥¹%‘•¹Ñ¥Ñä¹¥‘•¹Ñ¥Ñå%¤ì(€ô¤ì(€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡•¹É½±±•°mì¥‘•¹Ñ¥Ñå%è…‘µ¥¹%‘•¹Ñ¥Ñä¹¥‘•¹Ñ¥Ñå%õt¤ì)ô¤ì()Ñ•ÍÐ ‰É•™ÕÍ”Á…È“¥™…ÕÐÕ¹”“¥¥Í¥½¸Í…¹Ì…‘…ÁÑ…Ñ•ÕÈ…ÕÑ¡•¹Ñ¥™¥…Ñ¥½¸ˆ°…Íå¹Œ€ ¤€ôøì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡íô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡Á…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÐÀÄ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤°ì•ÉÉ½Èè€‰…ÕÑ¡•¹Ñ¥…Ñ¥½¹}É•ÅÕ¥É•ˆô¤ì(€€€…ÍÍ•ÉÐ¹µ…Ñ ¡É•ÍÁ½¹Í”¹¡•…‘•ÉÌ¹•Ð ‰àµ½ÉÉ•±…Ñ¥½¸µ¥ˆ¤°€½ylÀ´å„µ˜µuìÌÙô¼¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰Ë¥Ù½ÅÕ”Õ¹”Í•ÍÍ¥½¸Õ¹¥ÅÕ•µ•¹ÐÁ½ÕÈ°…ÁÁ±¥…Ñ¥½¸Ñ•¡¹¥ÅÕ”ÁÉ½ÁÉ§¥Ñ…¥É”ˆ°…Íå¹Œ€ ¤€ôøì(€±•ÐÉ•Ù½…Ñ¥½¸ì(€½¹ÍÐ…ÕÑ¡•¹Ñ¥…Ñ”€ô…Íå¹Œ€ ¤€ôø€¡ì(€€€…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°…Õ‘¥•¹”è€‰Ñ…Í­Ìˆ°½ÉÉ•±…Ñ¥½¹%è€‰½ÉÉ•±…Ñ¥½¸µÍ•ÍÍ¥½¸µÉ•Ù½­”ˆ°(€ô¤ì(€½¹ÍÐÍ•ÍÍ¥½¹ÕÑ¡½É¥Ñä€ôì(€€€É•Ù½­•½ÉÁÁ±¥…Ñ¥½¸è…Íå¹Œ€¡É•ÅÕ•ÍÐ¤€ôøì(€€€€€É•Ù½…Ñ¥½¸€ôÉ•ÅÕ•ÍÐì(€€€€€É•ÑÕÉ¸ìÉ•Ù½­•èÑÉÕ”°É•…Í½¹½‘”è€‰Í•ÍÍ¥½¹}É•Ù½­•ˆôì(€€€ô°(€ôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì…ÕÑ¡•¹Ñ¥…Ñ”°Í•ÍÍ¥½¹ÕÑ¡½É¥Ñäô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…ÁÁ±¥…Ñ¥½¸µÍ•ÍÍ¥½¹Ì½É•Ù½­•€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°(€€€€€¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°(€€€€€‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡ì(€€€€€€€…ÁÁ±¥…Ñ¥½¹}¥è€‰Ñ…Í­Ìˆ°(€€€€€€€¥‘•¹Ñ¥Ñå}¥è€‰¥‘•¹Ñ¥Ñä´Äˆ°(€€€€€€€Í•ÍÍ¥½¹}¥è€‰Í•ÍÍ¥½¸´Äˆ°(€€€€€ô¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÈÀÀ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤°ìÉ•Ù½­•èÑÉÕ”°É•…Í½¹}½‘”è€‰Í•ÍÍ¥½¹}É•Ù½­•ˆô¤ì(€ô¤ì(€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡É•Ù½…Ñ¥½¸°ì(€€€…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°(€€€¥‘•¹Ñ¥Ñå%è€‰¥‘•¹Ñ¥Ñä´Äˆ°(€€€Í•ÍÍ¥½¹%è€‰Í•ÍÍ¥½¸´Äˆ°(€€€É•…Í½¸è€‰¥½¹¹•á¥½¸‘•µ…¹“¥”‘…¹Ì8ÀäƒŠLMÕ¥Ù¤‘•ÌÓ‰¡•Ìˆ°(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰™•Éµ”°…¡Ì!QQ@±½ÉÍÅÕ”±„Í•ÍÍ¥½¸…ÁÁ±¥…Ñ¥Ù”•¹ÑÉ…±”•ÍÐË¥Ù½Å×¥”ˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐ…ÕÑ¡•¹Ñ¥…Ñ”€ô…Íå¹Œ€ ¤€ôø€¡ì(€€€…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°…Õ‘¥•¹”è€‰Ñ…Í­Ìˆ°½ÉÉ•±…Ñ¥½¹%è€‰½ÉÉ•±…Ñ¥½¸µÍ•ÍÍ¥½¸µ‘•¹¥•ˆ°(€ô¤ì(€½¹ÍÐÍ•ÍÍ¥½¹ÕÑ¡½É¥Ñä€ôì(€€€…ÍÍ•ÍÌè…Íå¹Œ€ ¤€ôø€¡ì…±±½Ý•è™…±Í”°É•…Í½¹½‘”è€‰Í•ÍÍ¥½¹}É•Ù½­•ˆô¤°(€ôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì…ÕÑ¡•¹Ñ¥…Ñ”°Í•ÍÍ¥½¹ÕÑ¡½É¥Ñäô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°(€€€€€¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°(€€€€€‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡ì€¸¸¹Á…å±½…°Í•ÍÍ¥½¹}¥è€‰Í•ÍÍ¥½¸´Äˆ°Í•ÍÍ¥½¹}Í•É•Ðè€‰Í•É•Ð´Äˆô¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÈÀÀ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤°ì…±±½Ý•è™…±Í”°É•…Í½¹}½‘”è€‰Í•ÍÍ¥½¹}É•Ù½­•ˆô¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰ÑÉ…¹ÍÁ½ÉÑ”Õ¹”“¥¥Í¥½¸…ÕÑ¡•¹Ñ¥™§¥”Í…¹Ìµ½‘¥™¥•ÈÍ½¸½¹ÑÉ…Ðˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐ…ÕÑ¡•¹Ñ¥…Ñ”€ô…Íå¹Œ€ ¤€ôø€¡ì(€€€…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°…Õ‘¥•¹”è€‰Ñ…Í­Ìˆ°½ÉÉ•±…Ñ¥½¹%è€ˆÀÀÀÀÀÀÀÀ´ÀÀÀÀ´ÐÀÀÀ´àÀÀÀ´ÀÀÀÀÀÀÀÀÀÀÀäˆ°(€ô¤ì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì…ÕÑ¡•¹Ñ¥…Ñ”ô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡Á…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÈÀÀ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤°ì…±±½Ý•èÑÉÕ”°É•…Í½¹}½‘”è€‰…•ÍÍ}É…¹Ñ•ˆô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹¡•…‘•ÉÌ¹•Ð ‰àµ½ÉÉ•±…Ñ¥½¸µ¥ˆ¤°€ˆÀÀÀÀÀÀÀÀ´ÀÀÀÀ´ÐÀÀÀ´àÀÀÀ´ÀÀÀÀÀÀÀÀÀÀÀäˆ¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰É—½¥ÐÕ¸…Ñ…±½Õ”Õ¹¥ÅÕ•µ•¹Ð‘”³Še…ÁÁ±¥…Ñ¥½¸Ñ•¡¹¥ÅÕ”ÁÉ½ÁÉ§¥Ñ…¥É”ˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐ…Ñ…±½I•Á½Í¥Ñ½Éä€ô¹•ÜQÉ…¹Í…Ñ¥½¹…±5•µ½ÉåI•Á½Í¥Ñ½Éä ¤ì(€…Ñ…±½I•Á½Í¥Ñ½Éä¹Í…Ù•ÁÁ±¥…Ñ¥½¸¡ì(€€€…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°‘¥ÍÁ±…å9…µ”è€‰S‰¡•Ìˆ°ÍÑ…ÑÕÌè€‰…Ñ¥Ù”ˆ°É•¥ÍÑÉ…Ñ¥½¹A½±¥äè€‰±½Í•ˆ°(€ô°…‘µ¥¹Õ‘¥Ð ‰…ÁÁ±¥…Ñ¥½¸¹É•¥ÍÑ•É•ˆ°ì…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆô¤¤ì(€½¹ÍÐ…Ñ…±½A…å±½…€ôì(€€€…ÁÁ±¥…Ñ¥½¹}¥è€‰Ñ…Í­Ìˆ°…Ñ…±½}Ù•ÉÍ¥½¸è€Ä°(€€€Á•Éµ¥ÍÍ¥½¹ÌèmìÁ•Éµ¥ÍÍ¥½¹}¥è€‰Ñ…Í­ÌéÉ•…ˆ°‘¥ÍÁ±…å}¹…µ”è€‰1¥É”ˆ°‘•ÍÉ¥ÁÑ¥½¸è€‰½¹ÍÕ±Ñ•È±•ÌÓ‰¡•Ì¸ˆ°ÍÑ…ÑÕÌè€‰…Ñ¥Ù”ˆõt°(€€€Í½Á•}ÑåÁ•ÌèmìÍ½Á•}ÑåÁ•}¥è€‰±½‰…°ˆ°‘¥ÍÁ±…å}¹…µ”è€‰±½‰…°ˆ°‘•ÍÉ¥ÁÑ¥½¸è€‰Q½ÕÑ”³Še…ÁÁ±¥…Ñ¥½¸¸ˆ°ÍÑ…ÑÕÌè€‰…Ñ¥Ù”ˆõt°(€€€É½±•ÌèmìÉ½±•}¥è€‰Ñ…Í­ÌµÉ•…‘•Èˆ°‘¥ÍÁ±…å}¹…µ”è€‰1•Ñ•ÕÈˆ°‘•ÍÉ¥ÁÑ¥½¸è€‰1•ÑÕÉ”±½‰…±”¸ˆ°ÍÑ…ÑÕÌè€‰…Ñ¥Ù”ˆ°Á•Éµ¥ÍÍ¥½¹Ìèl‰Ñ…Í­ÌéÉ•…‰t°Í½Á•}ÑåÁ•Ìèl‰±½‰…°‰tõt°(€€€ÁÉ½Ù¥Í¥½¹¥¹œèì(€€€€€µ½‘”è€‰ÁÉ••á¥ÍÑ¥¹}ÁÉ½™¥±•}É•ÅÕ¥É•ˆ°¥‘•¹Ñ¥Ñå}­•äè€‰¥‘•¹Ñ¥Ñå}¥ˆ°(€€€€€É•…‘¥¹•ÍÌè€‰…ÁÁ±¥…Ñ¥½¹}½¹™¥Éµ…Ñ¥½¹}É•ÅÕ¥É•ˆ°…ÕÑ½µ…Ñ¥}ÁÉ½™¥±•}É•…Ñ¥½¸è™…±Í”°(€€€€€•µ…¥±}µ…Ñ¡¥¹œè€‰™½É‰¥‘‘•¸ˆ°(€€€€€É•ÅÕ¥É•µ•¹ÑÌèmìÉ•ÅÕ¥É•µ•¹Ñ}¥è€‰±½…°µÁÉ½™¥±”ˆ°‘¥ÍÁ±…å}¹…µ”è€‰AÉ½™¥°±½…°ˆ°‘•ÍÉ¥ÁÑ¥½¸è€‰AÉ½™¥°½¹™¥É·¤Á…È³Še…ÁÁ±¥…Ñ¥½¸¸ˆõt°(€€€ô°(€ôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì(€€€É•Á½Í¥Ñ½Éäè…Ñ…±½I•Á½Í¥Ñ½Éä°(€€€…ÕÑ¡•¹Ñ¥…Ñ”è…Íå¹Œ€ ¤€ôø€¡ì…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°…Õ‘¥•¹”è€‰Ñ…Í­Ìˆô¤°(€ô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…ÁÁ±¥…Ñ¥½¸µ…•ÍÌµ…Ñ…±½Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡…Ñ…±½A…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÈÀÄ¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…° ¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤¤¹É•…Ñ•°ÑÉÕ”¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡…Ñ…±½I•Á½Í¥Ñ½Éä¹•Ñ1…Ñ•ÍÑÁÁ±¥…Ñ¥½¹•ÍÍ…Ñ…±½œ ‰Ñ…Í­Ìˆ¤¹…Ñ…±½Y•ÉÍ¥½¸°€Ä¤ì(€ô¤ì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ìÉ•Á½Í¥Ñ½Éäè…Ñ…±½I•Á½Í¥Ñ½Éäô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…ÁÁ±¥…Ñ¥½¸µ…•ÍÌµ…Ñ…±½Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡…Ñ…±½A…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÐÀÄ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•ÍÁ½¹Í”¹©Í½¸ ¤°ì•ÉÉ½Èè€‰…ÕÑ¡•¹Ñ¥…Ñ¥½¹}É•ÅÕ¥É•ˆô¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰…•ÁÑ”±„“¥¥Í¥½¸Í¥»¥”Á…È³Še¥‘•¹Ñ¥Ó¤Ñ•¡¹¥ÅÕ”•Ð‰±½ÅÕ”Í½¸É•©•Ôˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐ±¥•¹Ñ%€ô€‰Ñ…Í­ÌµÁÉ•ÁÉ½ˆì(€½¹ÍÐÍ•É•Ð€ô€‰„µÁÉ½Ñ•Ñ•µÑ•ÍÐµÍ•É•ÐµÝ¥Ñ µ…Ðµ±•…ÍÐ´ÌÈµ¡…É…Ñ•ÉÌˆì(€½¹ÍÐÑ¥µ•ÍÑ…µÀ€ôMÑÉ¥¹œ¡…Ñ”¹¹½Ü ¤¤ì(€½¹ÍÐ¹½¹”€ôÉ…¹‘½µUU% ¤ì(€½¹ÍÐÉ…Ý	½‘ä€ô)M=8¹ÍÑÉ¥¹¥™ä¡Á…å±½…¤ì(€½¹ÍÐÍ¥¹…ÑÕÉ”€ôÍ¥¹%¹Ñ•É¹…±I•ÅÕ•ÍÐ¡Í•É•Ð°ì(€€€µ•Ñ¡½è€‰A=MPˆ°Á…Ñ¡¹…µ”è€ˆ½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Ìˆ°Ñ¥µ•ÍÑ…µÀ°¹½¹”°É…Ý	½‘ä°(€ô¤ì(€½¹ÍÐ¡•…‘•ÉÌ€ôì(€€€€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆ°(€€€m%9QI91}1%9Q}!IL¹±¥•¹Ñ%‘tè±¥•¹Ñ%°(€€€m%9QI91}1%9Q}!IL¹Ñ¥µ•ÍÑ…µÁtèÑ¥µ•ÍÑ…µÀ°(€€€m%9QI91}1%9Q}!IL¹¹½¹•tè¹½¹”°(€€€m%9QI91}1%9Q}!IL¹Í¥¹…ÑÕÉ•tèÍ¥¹…ÑÕÉ”°(€ôì(€½¹ÍÐ…ÕÑ¡•¹Ñ¥…Ñ”€ôÉ•…Ñ•%¹Ñ•É¹…±±¥•¹ÑÕÑ¡•¹Ñ¥…Ñ½È¡ì(€€€±¥•¹ÑÌè¹•Ü5…À¡mm±¥•¹Ñ%°ì…ÁÁ±¥…Ñ¥½¹%è€‰Ñ…Í­Ìˆ°Í•É•Ðõut¤°(€ô¤ì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì…ÕÑ¡•¹Ñ¥…Ñ”ô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐ…•ÁÑ•€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌ°‰½‘äèÉ…Ý	½‘ä°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡…•ÁÑ•¹ÍÑ…ÑÕÌ°€ÈÀÀ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥Ð…•ÁÑ•¹©Í½¸ ¤°ì…±±½Ý•èÑÉÕ”°É•…Í½¹}½‘”è€‰…•ÍÍ}É…¹Ñ•ˆô¤ì((€€€½¹ÍÐÉ•Á±…å•€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌ°‰½‘äèÉ…Ý	½‘ä°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•Á±…å•¹ÍÑ…ÑÕÌ°€ÐÀÄ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡…Ý…¥ÐÉ•Á±…å•¹©Í½¸ ¤°ì•ÉÉ½Èè€‰…ÕÑ¡•¹Ñ¥…Ñ¥½¹}É•ÅÕ¥É•ˆô¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰É•™ÕÍ”±•Ì™½Éµ…ÑÌ°·¥Ñ¡½‘•Ì•ÐÙ½±Õµ•Ì¹½¸…ÕÑ½É¥Ï¥Ìˆ°…Íå¹Œ€ ¤€ôøì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ìµ…á	½‘å	åÑ•Ìè€ÄØô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÝÉ½¹5•Ñ¡½€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡ÝÉ½¹5•Ñ¡½¹ÍÑ…ÑÕÌ°€ÐÀÔ¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡ÝÉ½¹5•Ñ¡½¹¡•…‘•ÉÌ¹•Ð ‰…±±½Üˆ¤°€‰A=MPˆ¤ì((€€€½¹ÍÐÝÉ½¹QåÁ”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ìµ•Ñ¡½è€‰A=MPˆ°‰½‘äè€‰íôˆô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡ÝÉ½¹QåÁ”¹ÍÑ…ÑÕÌ°€ÐÄÔ¤ì((€€€½¹ÍÐÑ½½1…É”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡Á…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡Ñ½½1…É”¹ÍÑ…ÑÕÌ°€ÐÄÌ¤ì(€ô¤ì)ô¤ì()Ñ•ÍÐ ‰¸•áÁ½Í”©…µ…¥Ì±”“¥Ñ…¥°Õ¹”Á…¹¹”¥¹Ñ•É¹”ˆ°…Íå¹Œ€ ¤€ôøì(€½¹ÍÐ…ÕÑ¡•¹Ñ¥…Ñ”€ô…Íå¹Œ€ ¤€ôøìÑ¡É½Ü¹•ÜÉÉ½È ‰Í•É•Ð‘¥…¹½ÍÑ¥Œˆ¤ìôì(€…Ý…¥ÐÝ¥Ñ¡M•ÉÙ•È¡ì…ÕÑ¡•¹Ñ¥…Ñ”ô°…Íå¹Œ€¡‰…Í•UÉ°¤€ôøì(€€€½¹ÍÐÉ•ÍÁ½¹Í”€ô…Ý…¥Ð™•Ñ ¡€‘í‰…Í•UÉ±ô½¥¹Ñ•É¹…°½ØÄ½…•ÍÌµ‘•¥Í¥½¹Í€°ì(€€€€€µ•Ñ¡½è€‰A=MPˆ°¡•…‘•ÉÌèì€‰½¹Ñ•¹ÐµÑåÁ”ˆè€‰…ÁÁ±¥…Ñ¥½¸½©Í½¸ˆô°‰½‘äè)M=8¹ÍÑÉ¥¹¥™ä¡Á…å±½…¤°(€€€ô¤ì(€€€…ÍÍ•ÉÐ¹•ÅÕ…°¡É•ÍÁ½¹Í”¹ÍÑ…ÑÕÌ°€ÔÀÀ¤ì(€€€½¹ÍÐÉ•ÍÁ½¹Í•Q•áÐ€ô…Ý…¥ÐÉ•ÍÁ½¹Í”¹Ñ•áÐ ¤ì(€€€…ÍÍ•ÉÐ¹‘••ÁÅÕ…°¡)M=8¹Á…ÉÍ”¡É•ÍÁ½¹Í•Q•áÐ¤°ì•ÉÉ½Èè€‰¥¹Ñ•É¹…±}•ÉÉ½Èˆô¤ì(€€€…ÍÍ•ÉÐ¹‘½•Í9½Ñ5…Ñ ¡É•ÍÁ½¹Í•Q•áÐ°€½Í•É•Ð‘¥…¹½ÍÑ¥Œ¼¤ì(€ô¤ì)ô¤ì