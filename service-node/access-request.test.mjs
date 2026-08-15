import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { ACCESS_DECISION_PERMISSION } from "./access-decision-admin.mjs";
import {
  approveAccessRequestLine, refuseAccessRequestLine, submitPublicAccessRequest,
} from "./access-request.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operatorId = "60a40cd7-f2a4-4393-8021-9f806b42b41a";
const targetId = "70a40cd7-f2a4-4393-8021-9f806b42b41b";
const applicationId = "n09-suivi-taches";

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: "success", source: "access-request-tests",
    correlationId: randomUUID(), justification: "Préparation reproductible du test", ...changes,
  });
}

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity({
    identityId: operatorId, email: "operator@example.test", displayName: "Opérateur", status: "active",
  }, audit("identity.created", { subjectId: operatorId }));
  repository.saveIdentity({
    identityId: targetId, email: "person@example.test", displayName: "Personne", status: "active",
  }, audit("identity.created", { subjectId: targetId }));
  repository.saveApplication({
    applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration",
    status: "active", registrationPolicy: "closed",
  }, audit("application.registered", { applicationId: ADMIN_APPLICATION_ID }));
  repository.saveApplication({
    applicationId, displayName: "N09 – Suivi des tâches",
    status: "active", registrationPolicy: "approval",
  }, audit("application.registered", { applicationId }));
  repository.saveAssignment({
    assignmentId: randomUUID(), subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID,
    roleId: "access-decision-administrator", permissions: [ACCESS_DECISION_PERMISSION],
    scopeType: null, scopeId: null, conditions: [], status: "active",
    validFrom: null, validUntil: null, reason: "Administration des demandes d’accès",
    decidedBy: operatorId, inheritedFromGroup: null, version: 1,
  }, audit("assignment.created", { subjectId: operatorId, applicationId: ADMIN_APPLICATION_ID }));
  repository.publishApplicationAccessCatalog({
    applicationId, catalogVersion: 1,
    roles: [{
      role_id: "task-reader", displayName: "Lecteur", description: "Lecture des tâches autorisées.",
      status: "active", permissions: ["tasks:read"], scopeTypes: ["global"],
    }],
    permissions: [{
      permission_id: "tasks:read", displayName: "Lire", description: "Lire les tâches autorisées.", status: "active",
    }],
    scopeTypes: [{
      scope_type_id: "global", displayName: "Global", description: "Ensemble autorisé.", status: "active",
    }],
    provisioning: {
      mode: "central_identity_only", identity_key: "identity_id", readiness: "immediate",
      automatic_profile_creation: false, email_matching: "forbidden", requirements: [],
    },
  }, audit("application_access_catalog.published", { applicationId }));
  return repository;
}

test("enregistre une demande publique sans créer de droit implicite", async () => {
  const repository = seededRepository();
  const result = await submitPublicAccessRequest(repository, {
    displayName: "  Personne candidate  ", email: " CANDIDATE@example.test ",
    applicationIds: [applicationId],
    reason: "Accéder au suivi partagé pour les besoins de l’équipe.",
  });
  const requests = repository.listAccessRequests("pending");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].requestId, result.requestId);
  assert.equal(requests[0].applicantEmail, "candidate@example.test");
  assert.equal(requests[0].lines[0].status, "pending");
  assert.deepEqual(repository.listAssignments(targetId, applicationId), []);

  const duplicate = await submitPublicAccessRequest(repository, {
    displayName: "Personne candidate", email: "candidate@example.test",
    applicationIds: [applicationId], reason: "Nouvelle tentative sans multiplier les dossiers ouverts.",
  });
  assert.equal(duplicate.requestId, result.requestId);
  assert.equal(repository.listAccessRequests("pending").length, 1);
});

test("approuve une ligne et crée atomiquement l’affectation publiée", async () => {
  const repository = seededRepository();
  await submitPublicAccessRequest(repository, {
    displayName: "Personne candidate", email: "candidate@example.test",
    applicationIds: [applicationId], reason: "Accéder au suivi partagé pour les besoins de l’équipe.",
  });
  const line = repository.listAccessRequests("pending")[0].lines[0];
  const result = await approveAccessRequestLine(repository, {
    lineId: line.lineId, identityId: targetId, roleId: "task-reader",
    scopeType: "global", catalogVersion: 1, operatorIdentityId: operatorId,
    justification: "Accès de lecture validé pour le suivi partagé de l’équipe.",
  });
  assert.equal(result.line.status, "approved");
  assert.equal(result.request.status, "approved");
  const assignments = repository.listAssignments(targetId, applicationId);
  assert.equal(assignments.length, 1);
  assert.deepEqual(assignments[0].permissions, ["tasks:read"]);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse une ligne avec justification sans créer d’affectation", async () => {
  const repository = seededRepository();
  await submitPublicAccessRequest(repository, {
    displayName: "Personne candidate", email: "candidate@example.test",
    applicationIds: [applicationId], reason: "Accéder au suivi partagé pour un essai ponctuel.",
  });
  const line = repository.listAccessRequests("pending")[0].lines[0];
  const result = await refuseAccessRequestLine(repository, {
    lineId: line.lineId, operatorIdentityId: operatorId,
    justification: "Le besoin ponctuel ne justifie pas l’ouverture d’un accès durable.",
  });
  assert.equal(result.line.status, "refused");
  assert.equal(result.request.status, "refused");
  assert.deepEqual(repository.listAssignments(targetId, applicationId), []);
});
