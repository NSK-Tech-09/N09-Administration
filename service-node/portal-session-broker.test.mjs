import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createApplicationSessionAuthority } from "./application-session-authority.mjs";
import {
  issuePortalSession, openPortalSession, portalDirectory, portalOriginsFromEnvironment,
  PORTAL_APPLICATION_ID, safePortalReturn,
} from "./portal-session-broker.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "fred@example.test", displayName: "Fred", status: "active",
};
const sessionSecret = "P".repeat(48);
const audit = (action, applicationId = null) => createAuditEvent({
  action, result: "success", source: "portal-tests", correlationId: randomUUID(),
  subjectId: identity.identityId, applicationId, justification: "Préparation du test portail central",
});

function seeded({ portalAccess = true } = {}) {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created"));
  for (const application of [
    { applicationId: PORTAL_APPLICATION_ID, displayName: "Portail", status: "active", registrationPolicy: "closed" },
    { applicationId: "n09-energie", displayName: "Énergie", status: "active", registrationPolicy: "closed" },
    { applicationId: "n09-archive", displayName: "Archive", status: "inactive", registrationPolicy: "closed" },
  ]) repository.saveApplication(application, audit("application.registered", application.applicationId));
  for (const [applicationId, permissions] of [
    [PORTAL_APPLICATION_ID, ["portal:read"]], ["n09-energie", ["energy:read"]], ["n09-archive", ["archive:read"]],
  ].filter(([applicationId]) => portalAccess || applicationId !== PORTAL_APPLICATION_ID)) repository.saveAssignment({
    assignmentId: randomUUID(), subjectId: identity.identityId, applicationId,
    roleId: `${applicationId}-user`, permissions, scopeType: null, scopeId: null,
    conditions: [], status: "active", validFrom: null, validUntil: null,
    reason: "Accès contrôlé de test", decidedBy: null, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", applicationId));
  const authority = createApplicationSessionAuthority({
    repository,
    config: {
      mode: "enforce", applicationId: PORTAL_APPLICATION_ID,
      idleTtlMs: 3_600_000, absoluteTtlMs: 14_400_000, touchIntervalMs: 300_000,
    },
  });
  return { repository, authority };
}

test("n'accepte que des origines HTTPS exactes et des retours autorisés", () => {
  const origins = portalOriginsFromEnvironment({ N09_PORTAL_ORIGINS: "https://nsktech.fr, https://www.nsktech.fr" });
  assert.deepEqual(origins, ["https://nsktech.fr", "https://www.nsktech.fr"]);
  assert.equal(safePortalReturn("https://nsktech.fr/#applications", origins), "https://nsktech.fr/#applications");
  assert.equal(safePortalReturn("https://evil.example/", origins, "https://nsktech.fr/"), "https://nsktech.fr/");
  assert.throws(() => portalOriginsFromEnvironment({ N09_PORTAL_ORIGINS: "http://nsktech.fr" }), /invalid portal origin/);
});

test("émet une session portail propre à son audience et restitue seulement les applications actives", async () => {
  const { repository, authority } = seeded();
  const value = await issuePortalSession({
    repository, sessionAuthority: authority, sessionSecret,
    identitySession: { ...identity, status: "authenticated" },
  });
  const session = openPortalSession(value, sessionSecret);
  const directory = await portalDirectory({ repository, sessionAuthority: authority, session });
  assert.equal(directory.identity.displayName, "Fred");
  assert.deepEqual(directory.applications, ["n09-energie"]);
});

test("refuse l'émission sans droit portail et la lecture après révocation", async () => {
  const { repository, authority } = seeded({ portalAccess: false });
  await assert.rejects(issuePortalSession({
    repository, sessionAuthority: authority, sessionSecret,
    identitySession: { ...identity, status: "authenticated" },
  }), /portal_access_denied/);
});
