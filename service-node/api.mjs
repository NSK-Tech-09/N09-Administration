import { randomUUID } from "node:crypto";
import { decideAccess } from "./access.mjs";

const ALLOWED_FIELDS = new Set([
  "identity_id",
  "application_id",
  "required_permission",
  "scope_type",
  "scope_id",
  "satisfied_conditions",
  "session_id",
  "session_secret",
]);

function prepareRequest(principal, payload) {
  if (!principal) return { error: [401, { error: "authentication_required" }] };
  if (principal.audience !== principal.applicationId) {
    return { error: [403, { error: "invalid_audience" }] };
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { error: [400, { error: "invalid_request" }] };
  }
  if (Object.keys(payload).some((field) => !ALLOWED_FIELDS.has(field))) {
    return { error: [400, { error: "invalid_request" }] };
  }
  const conditions = payload.satisfied_conditions ?? [];
  if (
    typeof payload.identity_id !== "string" ||
    typeof payload.application_id !== "string" ||
    typeof payload.required_permission !== "string" ||
    !Array.isArray(conditions) ||
    !conditions.every((condition) => typeof condition === "string")
  ) {
    return { error: [400, { error: "invalid_request" }] };
  }
  const hasSessionId = Object.hasOwn(payload, "session_id");
  const hasSessionSecret = Object.hasOwn(payload, "session_secret");
  if (hasSessionId !== hasSessionSecret ||
      (hasSessionId && (typeof payload.session_id !== "string" || typeof payload.session_secret !== "string"))) {
    return { error: [400, { error: "invalid_request" }] };
  }
  if (payload.application_id !== principal.applicationId) {
    return { error: [403, { error: "application_boundary_violation" }] };
  }
  return {
    conditions,
    sessionCredential: hasSessionId
      ? { sessionId: payload.session_id, secret: payload.session_secret }
      : null,
  };
}

function decisionResponse({ identity, application, assignments, payload, conditions, respond }) {
  if (!identity || !application) return respond(404, { error: "resource_not_found" });
  const decision = decideAccess({
    identity, application, assignments,
    requiredPermission: payload.required_permission,
    scopeType: payload.scope_type ?? null,
    scopeId: payload.scope_id ?? null,
    satisfiedConditions: conditions,
  });
  return respond(200, { allowed: decision.allowed, reason_code: decision.reasonCode });
}

export function evaluateAccessRequest({ repository, principal, payload }) {
  const correlationId = principal?.correlationId || randomUUID();
  const respond = (status, body) => ({ status, body, correlationId });
  const prepared = prepareRequest(principal, payload);
  if (prepared.error) return respond(...prepared.error);

  const identity = repository.getIdentity(payload.identity_id);
  const application = repository.getApplication(payload.application_id);
  return decisionResponse({
    identity, application,
    assignments: repository.listAssignments(payload.identity_id, payload.application_id),
    payload, conditions: prepared.conditions, respond,
  });
}

export async function evaluateAccessRequestAsync({ repository, principal, payload, sessionAuthority = null }) {
  const correlationId = principal?.correlationId || randomUUID();
  const respond = (status, body) => ({ status, body, correlationId });
  const prepared = prepareRequest(principal, payload);
  if (prepared.error) return respond(...prepared.error);

  if (sessionAuthority) {
    const sessionDecision = await sessionAuthority.assess({
      credential: prepared.sessionCredential,
      identityId: payload.identity_id,
      applicationId: payload.application_id,
    });
    if (!sessionDecision.allowed) {
      return respond(200, { allowed: false, reason_code: sessionDecision.reasonCode });
    }
  }

  const [identity, application, assignments] = await Promise.all([
    repository.getIdentity(payload.identity_id),
    repository.getApplication(payload.application_id),
    repository.listAssignments(payload.identity_id, payload.application_id),
  ]);
  return decisionResponse({
    identity, application, assignments,
    payload, conditions: prepared.conditions, respond,
  });
}
