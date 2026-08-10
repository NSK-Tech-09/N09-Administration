import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { SYNTHETIC_PREPROD } from "./synthetic-preprod.mjs";

export function assertSyntheticRetirementTarget({ database, allowRetirement, operatorIdentityId, justification }) {
  if (allowRetirement !== "true") throw new Error("synthetic retirement is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("synthetic retirement can only target preproduction");
  }
  if (typeof operatorIdentityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(operatorIdentityId)) {
    throw new Error("a valid operator identity id is required");
  }
  if (operatorIdentityId === SYNTHETIC_PREPROD.identity.identityId) {
    throw new Error("the synthetic identity cannot retire itself");
  }
  if (typeof justification !== "string" || justification.trim().length < 20 || justification.trim().length > 500) {
    throw new Error("an explicit retirement justification between 20 and 500 characters is required");
  }
}

function sameFields(actual, expected, fields) {
  return fields.every((field) => JSON.stringify(actual?.[field]) === JSON.stringify(expected[field]));
}

function retirementAudit(action, correlationId, operatorIdentityId, justification, context) {
  return createAuditEvent({
    action, result: "success", source: "synthetic-preprod-retirement", correlationId,
    actorId: operatorIdentityId, justification: justification.trim(), ...context,
  });
}

export async function retireSyntheticPreprod(repository, {
  database, allowRetirement, operatorIdentityId, justification, correlationId = randomUUID(),
} = {}) {
  assertSyntheticRetirementTarget({ database, allowRetirement, operatorIdentityId, justification });
  const operator = await repository.getIdentity(operatorIdentityId);
  if (!operator || operator.status !== "active") throw new Error("operator identity must exist and be active");

  const identity = await repository.getIdentity(SYNTHETIC_PREPROD.identity.identityId);
  const application = await repository.getApplication(SYNTHETIC_PREPROD.application.applicationId);
  const assignments = await repository.listAssignments(
    SYNTHETIC_PREPROD.identity.identityId, SYNTHETIC_PREPROD.application.applicationId,
  );
  const assignment = assignments.find((item) => item.assignmentId === SYNTHETIC_PREPROD.assignment.assignmentId);
  if (!identity && !application && !assignment) return { correlationId, changed: [] };
  if (!identity || !application || !assignment) throw new Error("synthetic retirement set is incomplete");
  if (!sameFields(identity, SYNTHETIC_PREPROD.identity, ["identityId", "email", "displayName"]) || !["active", "archived"].includes(identity.status)) {
    throw new Error("synthetic identity does not match the controlled definition");
  }
  if (!sameFields(application, SYNTHETIC_PREPROD.application, ["applicationId", "displayName", "registrationPolicy"]) || !["active", "retired"].includes(application.status)) {
    throw new Error("synthetic application does not match the controlled definition");
  }
  if (!sameFields(assignment, SYNTHETIC_PREPROD.assignment, [
    "assignmentId", "subjectId", "applicationId", "roleId", "permissions", "scopeType", "scopeId", "conditions",
  ]) || !(
    (assignment.status === "active" && assignment.version === 1) ||
    (assignment.status === "revoked" && assignment.version === 2)
  )) {
    throw new Error("synthetic assignment does not match the controlled definition");
  }

  const changed = [];
  if (assignment.status === "active") {
    await repository.saveAssignment({
      ...assignment, status: "revoked", reason: justification.trim(),
      decidedBy: operatorIdentityId, version: assignment.version + 1,
    }, retirementAudit("assignment.synthetic_revoked", correlationId, operatorIdentityId, justification, {
      subjectId: assignment.subjectId, applicationId: assignment.applicationId, roleId: assignment.roleId,
      previousValue: { status: assignment.status, version: assignment.version },
      newValue: { status: "revoked", version: assignment.version + 1 },
    }));
    changed.push("assignment");
  }
  if (identity.status === "active") {
    await repository.saveIdentity({ ...identity, status: "archived" }, retirementAudit(
      "identity.synthetic_archived", correlationId, operatorIdentityId, justification, {
        subjectId: identity.identityId, previousValue: { status: identity.status }, newValue: { status: "archived" },
      },
    ));
    changed.push("identity");
  }
  if (application.status === "active") {
    await repository.saveApplication({ ...application, status: "retired" }, retirementAudit(
      "application.synthetic_retired", correlationId, operatorIdentityId, justification, {
        applicationId: application.applicationId, previousValue: { status: application.status }, newValue: { status: "retired" },
      },
    ));
    changed.push("application");
  }
  return { correlationId, changed };
}
