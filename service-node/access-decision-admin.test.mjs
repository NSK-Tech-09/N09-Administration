import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  ACCESS_DECISION_PERMISSION,
  authorizeAccessDecisionAdministration,
  grantAccessAssignment,
  revokeAccessAssignment,
} from "./access-decision-admin.mjs";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { createAuditEvent } from "./audit.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const operator = {
  identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a",
  email: "operator@example.test",
  displayName: "Opérateur NSK",
  status: "active",
};
const target = {
  identityId: "70a40cd7-f2a4-4393-8021-9f806b42b41b",
  email: "target@example.test",
  displayName: "Cible NSK",
  status: "active",
};
const audit = (action, changes = {}) => createAuditEvent({
  action,
  result: "success",
  source: "access-decision-tests",
  correlationId: randomUUID(),
  justification: "Préparation reproductible du test",
  ...changes,
});

function assignment({
  assignmentId = randomUUID(),
  subjectId = target.identityId,
  applicationId = "n09-suivi-taches",
  roleId = "tasks-reader",
  permissions = ["tasks:read"],
} = {}) {
  return {
    assignmentId,
    subjectId,
    applicationId,
    roleId,
    permissions,
    scopeType: null,
    scopeId: null,
    conditions: [],
    status: "active",
    validFrom: null,
    validUntil: null,
    reason: "Accès initial contrôlé",
    decidedBy: operator.identityId,
    inheritedFromGroup: null,
    version: 1,
  };
}

function seededRepository() {
  const repository = new TransactionalMemoryRepository();
  for (const identity of [operator, target]) {
    repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  }
  for (const application of [
    { applicationId: ADMIN_APPLICATION_ID, displayName: "N09 – Administration", status: "active", registrationPolicy: "closed" },
    { applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches", status: "active", registrationPolicy: "closed" },
  ]) {
    repository.saveApplication(application, audit("application.registered", { applicationId: application.applicationId }));
  }
  repository.saveAssignment(assignment({
    subjectId: operator.identityId,
    applicationId: ADMIN_APPLICATION_ID,
    roleId: "access-decision-administrator",
    permissions: [ACCESS_DECISION_PERMISSION],
  }), audit("assignment.created", { subjectId: operator.identityId, applicationId: ADMIN_APPLICATION_ID }));
  return repository;
}

const tasksCatalog = {
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
    { role_id: "tasks-administrator", display_name: "Administrateur", description: "Administration future.", status: "planned", permissions: ["tasks:read"], scope_types: ["site"] },
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

async function publishTasksCatalog(repository) {
  const result = await publishApplicationAccessCatalog({
    repository,
    principal: { applicationId: "n09-suivi-taches", audience: "n09-suivi-taches" },
    payload: tasksCatalog,
  });
  assert.equal(result.status, 201);
}

test("accorde uniquement le pouvoir central de décision explicite", async () => {
  const repository = seededRepository();
  assert.equal((await authorizeAccessDecisionAdministration(repository, operator.identityId)).allowed, true);
  assert.equal((await authorizeAccessDecisionAdministration(repository, target.identityId)).allowed, false);
});

test("révoque une affectation avec version, opérateur et audit", async () => {
  const repository = seededRepository();
  const controlled = assignment();
  repository.saveAssignment(controlled, audit("assignment.created", {
    subjectId: controlled.subjectId,
    applicationId: controlled.applicationId,
  }));
  const before = repository.auditCount();
  const result = await revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
    correlationId: "revocation-correlation",
  });
  assert.equal(result.assignment.status, "revoked");
  assert.equal(result.assignment.version, 2);
  assert.equal(result.assignment.decidedBy, operator.identityId);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse la concurrence, une justification faible et un opérateur non autorisé", async () => {
  const repository = seededRepository();
  const controlled = assignment();
  repository.saveAssignment(controlled, audit("assignment.created", {
    subjectId: controlled.subjectId,
    applicationId: controlled.applicationId,
  }));
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 2,
    operatorIdentityId: operator.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
  }), /stale assignment version/);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "trop court",
  }), /justification/);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: controlled.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: target.identityId,
    justification: "Retrait demandé après fin du besoin applicatif",
  }), /not allowed/);
});

test("réserve le pouvoir de décision à une gouvernance dédiée", async () => {
  const repository = seededRepository();
  const [decisionAuthority] = repository.listAssignments(operator.identityId, ADMIN_APPLICATION_ID);
  await assert.rejects(revokeAccessAssignment(repository, {
    assignmentId: decisionAuthority.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Passage de relais soumis à une gouvernance séparée",
  }), /dedicated governance/);
});

test("accorde un rôle actif du catalogue avec les confirmations applicatives obligatoires", async () => {
  const repository = seededRepository();
  await publishTasksCatalog(repository);
  const before = repository.auditCount();
  const result = await grantAccessAssignment(repository, {
    identityId: target.identityId,
    applicationId: "n09-suivi-taches",
    roleId: "tasks-writer",
    scopeType: "site",
    scopeId: "site_09",
    catalogVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Contribution nécessaire sur le site pilote validé",
    correlationId: "grant-correlation",
  });
  assert.equal(result.created, true);
  assert.deepEqual(result.assignment.permissions, ["tasks:read", "tasks:write"]);
  assert.deepEqual(result.assignment.conditions, ["application-user-profile", "site-membership"]);
  assert.equal(result.assignment.scopeType, "site");
  assert.equal(result.assignment.scopeId, "site_09");
  assert.equal(result.assignment.decidedBy, operator.identityId);
  assert.equal(repository.auditCount(), before + 1);
  assert.equal(repository.auditSnapshot().at(-1).event.action, "assignment.granted");
  assert.equal(repository.verifyAuditChain(), true);
});

test("rend une resoumission identique idempotente", async () => {
  const repository = seededRepository();
  await publishTasksCatalog(repository);
  const input = {
    identityId: target.identityId, applicationId: "n09-suivi-taches", roleId: "tasks-writer",
    scopeType: "site", scopeId: "site_09", catalogVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Contribution nécessaire sur le site pilote validé",
  };
  const first = await grantAccessAssignment(repository, input);
  const auditAfterFirst = repository.auditCount();
  const second = await grantAccessAssignment(repository, input);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(second.assignment.assignmentId, first.assignment.assignmentId);
  assert.equal(repository.auditCount(), auditAfterFirst);
});

test("réactive la même affectation après révocation avec une nouvelle version", async () => {
  const repository = seededRepository();
  await publishTasksCatalog(repository);
  const input = {
    identityId: target.identityId, applicationId: "n09-suivi-taches", roleId: "tasks-writer",
    scopeType: "site", scopeId: "site_09", catalogVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Contribution nécessaire sur le site pilote validé",
  };
  const first = await grantAccessAssignment(repository, input);
  await revokeAccessAssignment(repository, {
    assignmentId: first.assignment.assignmentId,
    expectedVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Retrait temporaire pendant la revue du périmètre",
  });
  const restored = await grantAccessAssignment(repository, {
    ...input, justification: "Rétablissement validé après revue du périmètre",
  });
  assert.equal(restored.created, true);
  assert.equal(restored.assignment.assignmentId, first.assignment.assignmentId);
  assert.equal(restored.assignment.version, 3);
  assert.equal(restored.assignment.status, "active");
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse un rôle planifié, un catalogue périmé et une gouvernance centrale", async () => {
  const repository = seededRepository();
  await publishTasksCatalog(repository);
  const input = {
    identityId: target.identityId, applicationId: "n09-suivi-taches", roleId: "tasks-writer",
    scopeType: "site", scopeId: "site_09", catalogVersion: 1,
    operatorIdentityId: operator.identityId,
    justification: "Contribution nécessaire sur le site pilote validé",
  };
  await assert.rejects(grantAccessAssignment(repository, { ...input, roleId: "tasks-administrator" }), /role is not active/);
  await assert.rejects(grantAccessAssignment(repository, { ...input, catalogVersion: 2 }), /stale or missing/);
  await assert.rejects(grantAccessAssignment(repository, { ...input, applicationId: ADMIN_APPLICATION_ID }), /dedicated procedure/);
  await assert.rejects(grantAccessAssignment(repository, { ...input, operatorIdentityId: target.identityId }), /not allowed/);
});
