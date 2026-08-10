import { createHash, randomUUID } from "node:crypto";

const FORBIDDEN_FIELD_PARTS = [
  "password",
  "secret",
  "token",
  "session_id",
  "authorization",
  "credential",
];

function assertSafe(value, path = "event") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertSafe(child, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (FORBIDDEN_FIELD_PARTS.some((part) => normalized.includes(part))) {
      throw new Error(`forbidden audit field: ${path}.${key}`);
    }
    assertSafe(child, `${path}.${key}`);
  }
}

function canonicalValue(value) {
  if (value instanceof Date) {
    return value.toISOString().replace(/\.(\d{3})Z$/, (_, milliseconds) =>
      milliseconds === "000" ? "+00:00" : `.${milliseconds}000+00:00`,
    );
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value instanceof Set) return [...value].map(canonicalValue).sort();
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]),
  );
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.values(value).forEach(deepFreeze);
  return Object.freeze(value);
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function createAuditEvent({
  action,
  result,
  source,
  correlationId,
  actorId = null,
  subjectId = null,
  applicationId = null,
  cause = null,
  roleId = null,
  scopeType = null,
  scopeId = null,
  conditions = [],
  previousValue = null,
  newValue = null,
  justification = "",
  eventId = randomUUID(),
  occurredAt = new Date(),
}) {
  if (![action, result, source, correlationId].every((item) => typeof item === "string" && item.trim())) {
    throw new Error("action, result, source and correlationId are required");
  }
  const event = {
    action: action.trim(),
    actor_id: actorId,
    application_id: applicationId,
    cause,
    conditions: [...conditions].map(canonicalValue).sort(),
    correlation_id: correlationId,
    event_id: eventId,
    justification: justification.trim(),
    new_value: canonicalValue(newValue),
    occurred_at: canonicalValue(occurredAt),
    previous_value: canonicalValue(previousValue),
    result: result.trim(),
    role_id: roleId,
    scope_id: scopeId,
    scope_type: scopeType,
    source: source.trim(),
    subject_id: subjectId,
  };
  assertSafe(event);
  return deepFreeze(event);
}

export function eventHash(event, previousHash = "") {
  return createHash("sha256")
    .update(`${previousHash}\n${canonicalJson(event)}`, "utf8")
    .digest("hex");
}

export function verifyAuditChain(entries) {
  let previousHash = "";
  for (const entry of entries) {
    if (entry.previousHash !== previousHash) return false;
    if (entry.eventHash !== eventHash(entry.event, previousHash)) return false;
    previousHash = entry.eventHash;
  }
  return true;
}
