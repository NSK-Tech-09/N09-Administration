import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import {
  authorizeNotificationOperationsAdministration, NOTIFICATION_OPERATIONS_READ_PERMISSION,
} from "./notification-operations-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const identity = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test",
  displayName: "Opérateur",
  status: "active",
};
const audit = (action, changes = {}) => createAuditEvent({
  action, result: "success", source: "notification-operations-tests",
  correlationId: crypto.randomUUID(), justification: "Test de pouvoir dédié", ...changes,
});

function configuredRepository(permission = NOTIFICATION_OPERATIONS_READ_PERMISSION) {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  repository.saveAssignment({
    assignmentId: crypto.randomUUID(), subjectId: identity.identityId,
    applicationId: ADMIN_APPLICATION_ID, roleId: "notification-operations-reader",
    permissions: [permission], scopeType: null, scopeId: null, conditions: [], status: "active",
    validFrom: null, validUntil: null, reason: "Test", decidedBy: null,
    inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: identity.identityId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

test("autorise uniquement la permission dédiée à l’exploitation des notifications", async () => {
  assert.equal((await authorizeNotificationOperationsAdministration(
    configuredRepository(), identity.identityId,
  )).allowed, true);
  const denied = await authorizeNotificationOperationsAdministration(
    configuredRepository("administration:access:read"), identity.identityId,
  );
  assert.equal(denied.allowed, false);
});

test("refuse une identité absente ou suspendue", async () => {
  assert.equal((await authorizeNotificationOperationsAdministration(configuredRepository(), "")).allowed, false);
  const repository = configuredRepository();
  repository.saveIdentity({ ...identity, status: "suspended" }, audit("identity.suspended", {
    subjectId: identity.identityId, previousValue: { status: "active" },
  }));
  assert.equal((await authorizeNotificationOperationsAdministration(repository, identity.identityId)).allowed, false);
});
