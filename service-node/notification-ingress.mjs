import { randomUUID } from "node:crypto";
import { canonicalJson, createAuditEvent } from "./audit.mjs";
import { createHash } from "node:crypto";

const EVENT_TYPES = new Set([
  "task.created", "task.updated", "task.archived", "task.restored",
  "comment.created", "comment.updated",
  "reaction.added", "reaction.removed", "attachment.created",
]);
const FORBIDDEN_PAYLOAD_KEYS = /(?:^|_)(?:authorization|cookie|credential|email|password|secret|token)(?:_|$)/i;
const EVENT_FIELDS = new Set([
  "event_id", "event_type", "task_id", "site_id", "actor_id",
  "aggregate_id", "payload", "occurred_at",
]);

export class NotificationIngressError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "NotificationIngressError";
    this.code = code;
    this.status = status;
  }
}

function exactObject(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some((key) => !fields.has(key))) {
    throw new NotificationIngressError(code);
  }
}

function identifier(value, code) {
  if (typeof value !== "string" || !value || value.length > 64 || value !== value.trim() ||
      /[\u0000-\u001f\u007f]/.test(value)) {
    throw new NotificationIngressError(code);
  }
  return value;
}

function safePayload(value, depth = 0) {
  if (depth > 5 || value === undefined || typeof value === "function" ||
      typeof value === "symbol" || typeof value === "bigint") {
    throw new NotificationIngressError("invalid_notification_event_payload");
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new NotificationIngressError("invalid_notification_event_payload");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) throw new NotificationIngressError("invalid_notification_event_payload");
    return value.map((item) => safePayload(item, depth + 1));
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new NotificationIngressError("invalid_notification_event_payload");
  }
  const entries = Object.entries(value);
  if (entries.length > 50) throw new NotificationIngressError("invalid_notification_event_payload");
  const result = {};
  for (const [key, item] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || FORBIDDEN_PAYLOAD_KEYS.test(key)) {
      throw new NotificationIngressError("invalid_notification_event_payload");
    }
    result[key] = safePayload(item, depth + 1);
  }
  return result;
}

function prepareEvent(value, now) {
  exactObject(value, EVENT_FIELDS, "invalid_notification_event");
  if (!EVENT_TYPES.has(value.event_type)) {
    throw new NotificationIngressError("invalid_notification_event_type");
  }
  if (value.actor_id !== null && value.actor_id !== undefined && typeof value.actor_id !== "string") {
    throw new NotificationIngressError("invalid_actor_id");
  }
  const occurredAt = new Date(value.occurred_at);
  if (typeof value.occurred_at !== "string" || !Number.isFinite(occurredAt.valueOf()) ||
      occurredAt.toISOString() !== value.occurred_at || occurredAt.valueOf() > now.valueOf() + 5 * 60_000) {
    throw new NotificationIngressError("invalid_notification_event_time");
  }
  const payload = safePayload(value.payload);
  if (Buffer.byteLength(JSON.stringify(payload), "utf8") > 16_384) {
    throw new NotificationIngressError("invalid_notification_event_payload");
  }
  const event = {
    eventId: identifier(value.event_id, "invalid_notification_event_id"),
    eventType: value.event_type,
    taskId: identifier(value.task_id, "invalid_task_id"),
    siteId: identifier(value.site_id, "invalid_site_id"),
    actorId: value.actor_id === null || value.actor_id === undefined
      ? null : identifier(value.actor_id, "invalid_actor_id"),
    aggregateId: identifier(value.aggregate_id, "invalid_notification_aggregate_id"),
    payload,
    occurredAt: occurredAt.toISOString(),
  };
  return {
    ...event,
    eventHash: createHash("sha256").update(canonicalJson(event), "utf8").digest("hex"),
  };
}

export function prepareNotificationBatch(payload, { now = new Date() } = {}) {
  exactObject(payload, new Set(["contract_version", "events"]), "invalid_notification_batch");
  if (payload.contract_version !== 1) throw new NotificationIngressError("unsupported_notification_contract");
  if (!Array.isArray(payload.events) || payload.events.length < 1 || payload.events.length > 100) {
    throw new NotificationIngressError("invalid_notification_batch_size");
  }
  const events = payload.events.map((event) => prepareEvent(event, now));
  if (new Set(events.map((event) => event.eventId)).size !== events.length) {
    throw new NotificationIngressError("duplicate_notification_event_in_batch");
  }
  return Object.freeze({ contractVersion: 1, events: events.map(Object.freeze) });
}

export async function receiveNotificationEvents({
  repository, principal, payload, now = new Date(), source = "notification-ingress-api",
}) {
  if (!principal) return { status: 401, body: { error: "authentication_required" } };
  if (principal.audience !== principal.applicationId) {
    return { status: 403, body: { error: "invalid_audience" } };
  }
  let batch;
  try { batch = prepareNotificationBatch(payload, { now }); }
  catch (error) {
    if (error instanceof NotificationIngressError) return { status: error.status, body: { error: error.code } };
    throw error;
  }
  const application = await repository.getApplication(principal.applicationId);
  if (!application) return { status: 404, body: { error: "application_not_found" } };
  if (application.status !== "active") return { status: 409, body: { error: "application_not_active" } };
  const correlationId = principal.correlationId || randomUUID();
  const events = batch.events.map((event) => ({
    ...event, sourceApplicationId: principal.applicationId, receivedAt: now.toISOString(),
  }));
  const audits = new Map(events.map((event) => [event.eventId, createAuditEvent({
    action: "notification.event_received", result: "pending", source, correlationId,
    applicationId: principal.applicationId,
    newValue: {
      source_event_id: event.eventId, event_type: event.eventType,
      task_id: event.taskId, site_id: event.siteId,
      event_hash: event.eventHash, status: "pending",
    },
  })]));
  try {
    const result = await repository.receiveNotificationEvents(events, audits);
    return {
      status: result.created > 0 ? 202 : 200,
      body: {
        contract_version: batch.contractVersion,
        accepted: result.created,
        already_present: result.alreadyPresent,
      },
    };
  } catch (error) {
    if (error instanceof NotificationIngressError) return { status: error.status, body: { error: error.code } };
    throw error;
  }
}
