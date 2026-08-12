import { createHash, randomUUID } from "node:crypto";
import { canonicalJson, createAuditEvent } from "./audit.mjs";
import { signInternalRequest } from "./internal-client-auth.mjs";

const CHANNELS = new Set(["in_app", "email", "telegram", "push", "sms", "whatsapp"]);
const IMPORTANCE = new Set(["information", "action", "lifecycle", "security"]);
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class NotificationMaterializationError extends Error {
  constructor(code, status = 500) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function exactObject(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some((key) => !fields.has(key))) throw new NotificationMaterializationError(code);
}

function boundedString(value, { max, pattern = null, code }) {
  if (typeof value !== "string" || !value || value !== value.trim() || value.length > max ||
      /[\u0000-\u001f\u007f]/.test(value) || (pattern && !pattern.test(value))) {
    throw new NotificationMaterializationError(code);
  }
  return value;
}

function validateResolution(value, event) {
  exactObject(value, new Set(["contract_version", "event_id", "policy_version", "intents", "suppressed"]),
    "invalid_notification_resolution");
  if (value.contract_version !== 1 || value.event_id !== event.eventId || !Array.isArray(value.intents) ||
      value.intents.length > 1000) throw new NotificationMaterializationError("invalid_notification_resolution");
  const policyVersion = boundedString(value.policy_version, {
    max: 100, pattern: IDENTIFIER, code: "invalid_notification_policy_version",
  });
  exactObject(value.suppressed, new Set(["own_action", "preferences", "unlinked_identity"]),
    "invalid_notification_suppression");
  const suppressed = {};
  for (const key of ["own_action", "preferences", "unlinked_identity"]) {
    if (!Number.isSafeInteger(value.suppressed[key]) || value.suppressed[key] < 0) {
      throw new NotificationMaterializationError("invalid_notification_suppression");
    }
    suppressed[key] = value.suppressed[key];
  }
  const seen = new Set();
  const intents = value.intents.map((intent) => {
    exactObject(intent, new Set([
      "recipient_identity_id", "category", "importance", "title", "message", "context", "requested_channels",
    ]), "invalid_notification_intent");
    const recipientIdentityId = boundedString(intent.recipient_identity_id, {
      max: 36, pattern: UUID, code: "invalid_notification_recipient",
    });
    if (seen.has(recipientIdentityId)) throw new NotificationMaterializationError("duplicate_notification_recipient");
    seen.add(recipientIdentityId);
    const category = boundedString(intent.category, { max: 80, pattern: IDENTIFIER, code: "invalid_notification_category" });
    if (!IMPORTANCE.has(intent.importance)) throw new NotificationMaterializationError("invalid_notification_importance");
    const title = boundedString(intent.title, { max: 200, code: "invalid_notification_title" });
    const message = boundedString(intent.message, { max: 1000, code: "invalid_notification_message" });
    if (/@|https?:\/\/|password|secret|token/i.test(`${title}\n${message}`)) {
      throw new NotificationMaterializationError("sensitive_notification_content");
    }
    exactObject(intent.context, new Set(["application_id", "resource_type", "resource_id"]),
      "invalid_notification_context");
    const context = {
      applicationId: boundedString(intent.context.application_id, { max: 100, pattern: IDENTIFIER, code: "invalid_notification_context" }),
      resourceType: boundedString(intent.context.resource_type, { max: 80, pattern: IDENTIFIER, code: "invalid_notification_context" }),
      resourceId: boundedString(intent.context.resource_id, { max: 128, pattern: IDENTIFIER, code: "invalid_notification_context" }),
    };
    if (context.applicationId !== event.sourceApplicationId || context.resourceId !== event.taskId) {
      throw new NotificationMaterializationError("notification_context_mismatch");
    }
    if (!Array.isArray(intent.requested_channels) || !intent.requested_channels.includes("in_app") ||
        new Set(intent.requested_channels).size !== intent.requested_channels.length ||
        intent.requested_channels.some((channel) => !CHANNELS.has(channel))) {
      throw new NotificationMaterializationError("invalid_notification_channels");
    }
    return Object.freeze({ recipientIdentityId, category, importance: intent.importance, title, message,
      context, requestedChannels: [...intent.requested_channels] });
  });
  return Object.freeze({ policyVersion, suppressed: Object.freeze(suppressed), intents });
}

export function tasksNotificationResolverConfig(environment = process.env) {
  const origin = environment.N09_TASKS_NOTIFICATION_RESOLVER_ORIGIN?.trim().replace(/\/$/, "");
  const clientId = environment.N09_TASKS_NOTIFICATION_RESOLVER_CLIENT_ID?.trim();
  const secret = environment.N09_TASKS_NOTIFICATION_RESOLVER_CLIENT_SECRET?.trim();
  const timeoutMs = Number(environment.N09_TASKS_NOTIFICATION_RESOLVER_TIMEOUT_MS || 3_000);
  if (![origin, clientId, secret].some(Boolean)) return null;
  if (!origin || !clientId || !secret || secret.length < 32 || !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 || timeoutMs > 10_000) throw new Error("invalid tasks notification resolver configuration");
  const parsed = new URL(origin);
  if (parsed.protocol !== "https:" && environment.N09_ENVIRONMENT !== "test") {
    throw new Error("tasks notification resolver requires HTTPS");
  }
  return Object.freeze({ origin, clientId, secret, timeoutMs });
}

export function createTasksNotificationResolverClient({
  config, fetchImpl = fetch, now = () => Date.now(), createNonce = randomUUID,
} = {}) {
  if (!config) throw new Error("tasks notification resolver configuration is required");
  const pathname = "/internal/v1/notification-intents";
  return async function resolve(event) {
    const payload = { contract_version: 1, event: {
      event_id: event.eventId, event_type: event.eventType, task_id: event.taskId,
      site_id: event.siteId, actor_id: event.actorId, aggregate_id: event.aggregateId,
      payload: event.payload, occurred_at: event.occurredAt,
    } };
    const rawBody = JSON.stringify(payload);
    const timestamp = String(now());
    const nonce = createNonce();
    const headers = {
      accept: "application/json", "content-type": "application/json",
      "x-n09-client-id": config.clientId, "x-n09-timestamp": timestamp, "x-n09-nonce": nonce,
      "x-n09-signature": signInternalRequest(config.secret, {
        method: "POST", pathname, timestamp, nonce, rawBody,
      }),
    };
    let response;
    try {
      response = await fetchImpl(`${config.origin}${pathname}`, {
        method: "POST", headers, body: rawBody, signal: AbortSignal.timeout(config.timeoutMs),
      });
    } catch (cause) {
      throw new NotificationMaterializationError("notification_resolver_unavailable", 503, { cause });
    }
    let body;
    try { body = await response.json(); } catch {
      throw new NotificationMaterializationError("invalid_notification_resolver_response", 503);
    }
    if (response.status !== 200) {
      const code = response.status >= 500 ? "notification_resolver_unavailable" : "notification_resolution_rejected";
      throw new NotificationMaterializationError(code, 503);
    }
    return validateResolution(body, event);
  };
}

function stableId(...parts) {
  return createHash("sha256").update(parts.join("\n"), "utf8").digest("hex");
}

export function createNotificationEventHandler({ repository, resolve, now = () => new Date() } = {}) {
  if (!repository || typeof repository.materializeNotificationResolution !== "function") {
    throw new Error("notification materialization repository is required");
  }
  if (typeof resolve !== "function") throw new Error("notification resolver is required");
  return async function handle(event) {
    const resolution = await resolve(event);
    const createdAt = now();
    const notifications = resolution.intents.map((intent) => ({
      notificationId: stableId(event.sourceApplicationId, event.eventId, intent.recipientIdentityId),
      recipientIdentityId: intent.recipientIdentityId,
      category: intent.category, importance: intent.importance, title: intent.title, message: intent.message,
      contextApplicationId: intent.context.applicationId, contextResourceType: intent.context.resourceType,
      contextResourceId: intent.context.resourceId, occurredAt: event.occurredAt, createdAt,
    }));
    const externalDeliveries = notifications.flatMap((notification, index) =>
      resolution.intents[index].requestedChannels.filter((channel) => channel !== "in_app").map((channel) => ({
        deliveryId: stableId(notification.notificationId, channel), notificationId: notification.notificationId,
        channel, status: "blocked", blockedReason: "channel_not_enabled", createdAt,
      }))
    );
    const resolutionHash = createHash("sha256").update(canonicalJson({
      policyVersion: resolution.policyVersion,
      suppressed: resolution.suppressed,
      notifications: notifications.map(({ createdAt: _createdAt, ...stable }) => stable),
      externalDeliveries: externalDeliveries.map(({ createdAt: _createdAt, ...stable }) => stable),
    }), "utf8").digest("hex");
    const auditEvent = createAuditEvent({
      action: "notification.event_materialized", result: "success", source: "notification-consumer",
      correlationId: randomUUID(), applicationId: event.sourceApplicationId,
      newValue: {
        source_event_id: event.eventId, policy_version: resolution.policyVersion,
        internal_notifications: notifications.length, external_deliveries_blocked: externalDeliveries.length,
        suppressed: resolution.suppressed, resolution_hash: resolutionHash,
      },
    });
    return repository.materializeNotificationResolution({
      event, policyVersion: resolution.policyVersion, resolutionHash, suppressed: resolution.suppressed,
      notifications, externalDeliveries, resolvedAt: createdAt, auditEvent,
    });
  };
}
