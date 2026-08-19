import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { createHttpHandler } from "./http.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { OIDC_SESSION_COOKIE, seal } from "./oidc.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";
import {
  grantResponsibleAuthority, LEGAL_OWNER_CONFIRMATION, LEGAL_OWNER_EMAIL,
} from "./responsible-authority.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const oidcConfig = {
  clientId: "n09-client", clientSecret: "client-secret",
  redirectUri: "https://prod-admin.example.invalid/auth/infomaniak/callback",
  sessionSecret: "a-long-random-session-secret-with-32-chars",
};

async function repository() {
  const result = new TransactionalMemoryRepository();
  result.saveIdentity({
    identityId, email: LEGAL_OWNER_EMAIL, displayName: "Fred TRAVERS", status: "active",
  }, createAuditEvent({
    action: "identity.created", result: "success", source: "tests",
    correlationId: "authority-http-identity", subjectId: identityId,
  }));
  result.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "tests",
    correlationId: "authority-http-application", applicationId: ADMIN_APPLICATION_ID,
  }));
  await publishAdministrationAccessCatalog(result, {
    database: "n09_admin_preprod", allowBootstrap: "true", correlationId: "authority-http-catalog",
  });
  return result;
}

function sessionCookie() {
  const session = seal({
    sessionVersion: 2, identityId, displayName: "Utilisateur NSK Tech 09",
    providerKey: "infomaniak", status: "authenticated", csrf: "csrf-value",
    expiresAt: Date.now() + 60_000,
  }, oidcConfig.sessionSecret, "oidc-session");
  return `${OIDC_SESSION_COOKIE}=${session}`;
}

async function page(repository) {
  const server = createServer(createHttpHandler({ repository, oidcConfig }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/`, {
      headers: { cookie: sessionCookie() },
    });
    assert.equal(response.status, 200);
    return response.text();
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("signale au responsable les pouvoirs encore manquants", async () => {
  const body = await page(await repository());
  assert.match(body, /Poste de pilotage NSK Tech 09/);
  assert.match(body, /Responsable légal et opérationnel/);
  assert.match(body, /Autorité à compléter · 0\/8/);
  assert.equal(body.match(/Pouvoir manquant/g)?.length, 8);
  assert.match(body, /Bienvenue <strong>Fred TRAVERS<\/strong>/);
});

test("présente les huit accès de supervision après habilitation", async () => {
  const target = await repository();
  await grantResponsibleAuthority(target, {
    database: "n09_admin_prod", environment: "production", allowGrant: "true",
    confirmation: LEGAL_OWNER_CONFIRMATION, email: LEGAL_OWNER_EMAIL,
    justification: "Autorité complète du responsable légal et opérationnel de NSK Tech 09.",
  });
  const body = await page(target);
  assert.match(body, /Autorité complète · 8\/8/);
  assert.equal(body.match(/Pouvoir accordé/g)?.length, 8);
  assert.match(body, /Décisions d’accès/);
  assert.match(body, /Supervision des notifications/);
  assert.match(body, /Sorties de l’écosystème/);
});
