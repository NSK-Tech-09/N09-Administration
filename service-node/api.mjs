import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";

const ALLOWED_FIELDS = new Set([
  "identity_id",
  "application_id",
  "required_permission",
  "scope_type",
  "scope_id",
  "satisfied_conditions",
]);

export function evaluateAccessRequest({ repository, principal, payload }) {
  const correlationId = principal?.correlationId || randomUUID();
  const respond = (status, body) => ({ status, body, correlationId });
  if (!principal) return respond(401, { error: "authentication_required" });
  if (principal.audience !== principal.applicationId) {
    return respond(403, { error: "invalid_audience" });
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return respond(400, { error: "invalid_request" });
  }
  if (Object.keys(payload).some((field) => !ALLOWED_FIELDS.has(field))) {
    return respond(400, { error: "invalid_request" });
  }
  const conditions = payload.satisfied_conditions ?? [];
  if (
    typeof payload.identity_id !== "string" ||
    typeof payload.application_id !== "string" ||
    typeof payload.required_permission !== "string" ||
    !Array.isArray(conditions) ||
    !conditions.every((condition) => typeof condition === "string")
  ) {
    return respond(400, { error: "invalid_request" });
  }
  if (payload.application_id !== principal.applicationId) {
    return respond(403, { error: "application_boundary_violation" });
  }

  const identity = repository.getIdentity(payload.identity_id);
  const application = repository.getApplication(payload.application_id);
  if (!identity || !application) return respond(404, { error: "resource_not_found" });
  const decision = decideAccess({
    identity,
    application,
    assignments: repository.listAssignments(payload.identity_id, payload.application_id),
    requiredPermission: payload.required_permission,
    scopeType: payload.scope_type ?? null,
    scopeId: payload.scope_id ?? null,
    satisfiedConditions: conditions,
  });
  return respond(200, { allowed: decision.allowed, reason_code: decision.reasonCode });
}
