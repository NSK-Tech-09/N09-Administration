import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

export const SYNTHETIC_PREPROD = Object.freeze({
  identity: Object.freeze({
    identityId: "00000000-0000-4000-8000-000000000009",
    email: "synthetic-administrator@example.invalid",
    displayName: "Identité synthétique NSK Tech 09",
    status: "active",
  }),
  application: Object.freeze({
    applicationId: "n09-synthetic",
    displayName: "Application synthétique NSK Tech 09",
    status: "active",
    registrationPolicy: "closed",
  }),
  assignment: Object.freeze({
    assignmentId: "00000000-0000-4000-8000-000000000109",
    subjectId: "00000000-0000-4000-8000-000000000009",
    applicationId: "n09-synthetic",
    roleId: "synthetic-reader",
    permissions: Object.freeze(["synthetic:read"]),
    scopeType: null,
    scopeId: null,
    conditions: Object.freeze([]),
    status: "active",
    validFrom: null,
    validUntil: null,
    reason: "Validation technique avec données exclusivement synthétiques",
    decidedBy: null,
    inheritedFromGroup: null,
    version: 1,
  }),
});

export function assertSyntheticPreprodTarget({ database, allowSyntheticPreprod }) {
  if (allowSyntheticPreprod !== "true") throw new Error("synthetic preproduction seed is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("synthetic data can only target a preproduction database");
  }
}

function audit(action, correlationId, context = {}) {
  return createAuditEvent({
    action, result: "success", source: "synthetic-preprod-seed", correlationId,
    justification: "Jeu de validation synthétique, réversible et sans donnée utilisateur",
    ...context,
  });
}

function sameRecord(actual, expected) {
  if (!actual) return false;
  return Object.entries(expected).every(([key, value]) => JSON.stringify(actual[key]) === JSON.stringify(value));
}

export async function seedSyntheticPreprod(repository, {
  database,
  allowSyntheticPreprod,
  correlationId = randomUUID(),
} = {}) {
  assertSyntheticPreprodTarget({ database, allowSyntheticPreprod });
  const created = [];
  const identity = await repository.getIdentity(SYNTHETIC_PREPROD.identity.identityId);
  if (identity && !sameRecord(identity, SYNTHETIC_PREPROD.identity)) throw new Error("synthetic identity id collision");
  if (!identity) {
    await repository.saveIdentity(SYNTHETIC_PREPROD.identity, audit("identity.synthetic_created", correlationId, {
      subjectId: SYNTHETIC_PREPROD.identity.identityId, newValue: { synthetic: true },
    }));
    created.push("identity");
  }

  const application = await repository.getApplication(SYNTHETIC_PREPROD.application.applicationId);
  if (application && !sameRecord(application, SYNTHETIC_PREPROD.application)) throw new Error("synthetic application id collision");
  if (!application) {
    await repository.saveApplication(SYNTHETIC_PREPROD.application, audit("application.synthetic_registered", correlationId, {
      applicationId: SYNTHETIC_PREPROD.application.applicationId, newValue: { synthetic: true },
    }));
    created.push("application");
  }

  const assignments = await repository.listAssignments(
    SYNTHETIC_PREPROD.identity.identityId, SYNTHETIC_PREPROD.application.applicationId,
  );
  const assignment = assignments.find((item) => item.assignmentId === SYNTHETIC_PREPROD.assignment.assignmentId);
  if (assignment && !sameRecord(assignment, SYNTHETIC_PREPROD.assignment)) throw new Error("synthetic assignment id collision");
  if (!assignment) {
    await repository.saveAssignment(SYNTHETIC_PREPROD.assignment, audit("assignment.synthetic_created", correlationId, {
      subjectId: SYNTHETIC_PREPROD.identity.identityId,
      applicationId: SYNTHETIC_PREPROD.application.applicationId,
      roleId: SYNTHETIC_PREPROD.assignment.roleId,
      newValue: { synthetic: true },
    }));
    created.push("assignment");
  }
  return { correlationId, created };
}
