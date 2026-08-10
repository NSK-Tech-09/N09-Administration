import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  ADMIN_APPLICATION_ID, authorizeIdentityLinkAdministration, LINK_DECISION_PERMISSION,
} from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = { identityId: "identity-1", email: "admin@example.test", displayName: "Administrateur", status: "active" };
const application = { applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration", status: "active", registrationPolicy: "closed" };
const audit = (action, changes = {}) => createAuditEvent({
  action, result: "success", source: "tests", correlationId: crypto.randomUUID(),
  justification: "Test reproductible", ...changes,
});

function seededRepository({ permission = LINK_DECISION_PERMISSION, identityStatus = "active" } = {}) {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({ ...identity, status: identityStatus }, audit("identity.created", { subjectId: identity.identityId }));
  repository.saveApplication(application, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  repository.saveAssignment({
    assignmentId: "assignment-admin", subjectId: identity.identityId,
    applicationId: ADMIN_APPLICATION_ID, roleId: "identity-link-administrator",
    permissions: [permission], scopeType: null, scopeId: null, conditions: [],
    status: "active", validFrom: null, validUntil: null,
    reason: "Administration des identités", decidedBy: identity.identityId,
    inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: identity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

test("accorde uniquement la permission administrative dédiée", async () => {
  const decision = await authorizeIdentityLinkAdministration(seededRepository(), identity.identityId);
  assert.equal(decision.allowed, true);
  assert.equal(decision.assignment.roleId, "identity-link-administrator");
});

test("une identité simplement rattachée reste sans accès administratif", async () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  repository.saveApplication(application, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  const decision = await authorizeIdentityLinkAdministration(repository, identity.identityId);
  assert.equal(decision.allowed, false);
  assert.equal(decision.reasonCode, "assignment_missing");
});

test("un autre privilège ne remplace pas le droit de décision", async () => {
  const decision = await authorizeIdentityLinkAdministration(
    seededRepository({ permission: "administration:all" }), identity.identityId,
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.reasonCode, "permission_or_validity_missing");
});

test("une identité suspendue est refusée malgré son affectation", async () => {
  const decision = await authorizeIdentityLinkAdministration(
    seededRepository({ identityStatus: "suspended" }), identity.identityId,
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.reasonCode, "identity_not_active");
});
