import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { publishAdministrationAccessCatalog } from "./administration-access-catalog.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";
import {
  assessResponsibleAuthority, grantResponsibleAuthority, LEGAL_OWNER_CONFIRMATION,
  LEGAL_OWNER_EMAIL, RESPONSIBLE_AUTHORITY_POWERS,
} from "./responsible-authority.mjs";

const identityId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";

async function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId, email: LEGAL_OWNER_EMAIL, displayName: "Fred TRAVERS", status: "active",
  }, createAuditEvent({
    action: "identity.created", result: "success", source: "tests",
    correlationId: "responsible-authority-identity", subjectId: identityId,
  }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "tests",
    correlationId: "responsible-authority-application", applicationId: ADMIN_APPLICATION_ID,
  }));
  const published = await publishAdministrationAccessCatalog(repository, {
    database: "n09_admin_preprod", allowBootstrap: "true",
    correlationId: "responsible-authority-catalog",
  });
  assert.equal(published.catalogVersion, 7);
  return repository;
}

const grantInput = {
  database: "n09_admin_prod", environment: "production", allowGrant: "true",
  confirmation: LEGAL_OWNER_CONFIRMATION, email: LEGAL_OWNER_EMAIL,
  justification: "Autorité complète du responsable légal et opérationnel de NSK Tech 09.",
};

test("présente séparément les huit pouvoirs de responsabilité", async () => {
  const repository = await seededRepository();
  const before = await assessResponsibleAuthority(repository, identityId);
  assert.equal(before.legalOwner, true);
  assert.equal(before.complete, false);
  assert.equal(before.grantedCount, 0);
  assert.equal(before.totalCount, 8);
  assert.equal(new Set(before.powers.map((power) => power.permission)).size, 8);
});

test("accorde les huit pouvoirs explicites, audités et idempotents", async () => {
  const repository = await seededRepository();
  let sequence = 0;
  const assignmentId = () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`;
  const first = await grantResponsibleAuthority(repository, { ...grantInput, assignmentId });
  assert.equal(first.created.length, RESPONSIBLE_AUTHORITY_POWERS.length);
  assert.equal(first.unchanged.length, 0);
  const after = await assessResponsibleAuthority(repository, identityId);
  assert.equal(after.complete, true);
  assert.equal(after.grantedCount, 8);
  assert.equal(repository.listAssignments(identityId, ADMIN_APPLICATION_ID).length, 8);
  const auditCount = repository.auditCount();
  const second = await grantResponsibleAuthority(repository, { ...grantInput, assignmentId });
  assert.deepEqual(second.created, []);
  assert.equal(second.unchanged.length, 8);
  assert.equal(repository.auditCount(), auditCount);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse toute cible ou confirmation de production ambiguë", async () => {
  const repository = await seededRepository();
  await assert.rejects(grantResponsibleAuthority(repository, {
    ...grantInput, environment: "preprod",
  }), /requires production/);
  await assert.rejects(grantResponsibleAuthority(repository, {
    ...grantInput, database: "n09_admin_preprod",
  }), /production database/);
  await assert.rejects(grantResponsibleAuthority(repository, {
    ...grantInput, confirmation: "oui",
  }), /not explicitly confirmed/);
  await assert.rejects(grantResponsibleAuthority(repository, {
    ...grantInput, email: "autre@nsktech.fr",
  }), /unexpected legal owner email/);
});
