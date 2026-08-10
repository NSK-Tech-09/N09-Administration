import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

export const TASKS_APPLICATION = Object.freeze({
  applicationId: "n09-suivi-taches", displayName: "N09 – Suivi des tâches",
  status: "active", registrationPolicy: "closed",
});
export const TASKS_READ_PERMISSION = "tasks:read";

export function assertTasksPilotBootstrapTarget({ database, allowBootstrap, identityId, justification }) {
  if (allowBootstrap !== "true") throw new Error("tasks pilot bootstrap is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) throw new Error("tasks pilot bootstrap can only target preproduction");
  if (typeof identityId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identityId)) {
    throw new Error("a valid pilot identity id is required");
  }
  if (typeof justification !== "string" || justification.trim().length < 20 || justification.trim().length > 500) {
    throw new Error("an explicit pilot justification between 20 and 500 characters is required");
  }
}

export async function bootstrapTasksPilot(repository, {
  database, allowBootstrap, identityId, justification,
  correlationId = randomUUID(), assignmentId = randomUUID(),
} = {}) {
  assertTasksPilotBootstrapTarget({ database, allowBootstrap, identityId, justification });
  const identity = await repository.getIdentity(identityId);
  if (!identity || identity.status !== "active") throw new Error("pilot identity must exist and be active");
  const created = [];
  const application = await repository.getApplication(TASKS_APPLICATION.applicationId);
  if (application && JSON.stringify(application) !== JSON.stringify(TASKS_APPLICATION)) {
    throw new Error("tasks application conflicts with the controlled definition");
  }
  if (!application) {
    await repository.saveApplication(TASKS_APPLICATION, createAuditEvent({
      action: "application.registered", result: "success", source: "tasks-pilot-bootstrap",
      correlationId, applicationId: TASKS_APPLICATION.applicationId, justification,
      newValue: { status: "active", registration_policy: "closed" },
    }));
    created.push("application");
  }

  const existing = await repository.listAssignments(identityId, TASKS_APPLICATION.applicationId);
  if (!existing.some((item) => item.status === "active" && item.permissions.includes(TASKS_READ_PERMISSION))) {
    await repository.saveAssignment({
      assignmentId, subjectId: identityId, applicationId: TASKS_APPLICATION.applicationId,
      roleId: "tasks-pilot-reader", permissions: [TASKS_READ_PERMISSION],
      scopeType: null, scopeId: null, conditions: [], status: "active",
      validFrom: null, validUntil: null, reason: justification.trim(), decidedBy: null,
      inheritedFromGroup: null, version: 1,
    }, createAuditEvent({
      action: "assignment.created", result: "success", source: "tasks-pilot-bootstrap",
      correlationId, subjectId: identityId, applicationId: TASKS_APPLICATION.applicationId,
      roleId: "tasks-pilot-reader", justification,
      newValue: { status: "active", permissions: [TASKS_READ_PERMISSION] },
    }));
    created.push("assignment");
  }
  return { correlationId, created };
}
