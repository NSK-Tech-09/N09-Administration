import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import { emailLoginConfigFromEnvironment, normalizeLoginEmail } from "./email-login.mjs";

const WORKER_ID = /^[A-Za-z0-9._:-]{3,128}$/;
const ERROR_CODE = /^[a-z][a-z0-9_:-]{0,79}$/;

function integer(environment, name, fallback, minimum, maximum) {
  const value = Number(environment[name] || fallback);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`invalid ${name}`);
  return value;
}

function exactHttpsOrigin(value, name) {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" ||
      parsed.search || parsed.hash) throw new Error(`${name} must be an exact HTTPS origin`);
  return parsed.origin;
}

export function notificationEmailDeliveryConfig(environment = process.env) {
  if (environment.N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY !== "true") {
    throw new Error("external notification delivery is disabled");
  }
  if (!["preprod", "production"].includes(environment.N09_ENVIRONMENT)) {
    throw new Error("notification email delivery requires a managed environment");
  }
  const rawNotBefore = environment.N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE;
  const notBefore = new Date(rawNotBefore || "");
  if (!rawNotBefore || Number.isNaN(notBefore.valueOf()) || notBefore.toISOString() !== rawNotBefore) {
    throw new Error("invalid N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE");
  }
  const email = emailLoginConfigFromEnvironment(environment);
  if (!email.enabled) throw new Error("protected Brevo delivery is not configured");
  return Object.freeze({
    notBefore,
    tasksPublicOrigin: exactHttpsOrigin(environment.N09_TASKS_PUBLIC_ORIGIN, "N09_TASKS_PUBLIC_ORIGIN"),
    senderEmail: email.senderEmail, senderName: email.senderName, apiKey: email.apiKey,
    batchSize: integer(environment, "N09_NOTIFICATION_EMAIL_BATCH_SIZE", 20, 1, 100),
    maxAttempts: integer(environment, "N09_NOTIFICATION_EMAIL_MAX_ATTEMPTS", 5, 1, 20),
    leaseMs: integer(environment, "N09_NOTIFICATION_EMAIL_LEASE_MS", 60_000, 1_000, 3_600_000),
    retryBaseMs: integer(environment, "N09_NOTIFICATION_EMAIL_RETRY_BASE_MS", 60_000, 1_000, 86_400_000),
  });
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

export function createNotificationEmailDelivery(config, { fetchImpl = fetch } = {}) {
  if (!config?.apiKey || typeof fetchImpl !== "function") throw new Error("notification email delivery is incomplete");
  return Object.freeze({
    async send(delivery) {
      const to = normalizeLoginEmail(delivery.recipientEmail);
      const displayName = String(delivery.recipientDisplayName || "").trim();
      const taskUrl = `${config.tasksPublicOrigin}/tasks/${encodeURIComponent(delivery.contextResourceId)}`;
      const response = await fetchImpl("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { accept: "application/json", "api-key": config.apiKey, "content-type": "application/json" },
        body: JSON.stringify({
          sender: { email: config.senderEmail, name: config.senderName },
          to: [{ email: to, name: displayName }],
          subject: `${delivery.title} · N09 - Suivi des tâches`,
          textContent: `Bonjour ${displayName},\n\n${delivery.message}\n\nOuvrir la tâche :\n${taskUrl}\n\nCe message a été envoyé selon tes préférences de notification NSK Tech 09.`,
          htmlContent: `<p>Bonjour ${escapeHtml(displayName)},</p><p>${escapeHtml(delivery.message)}</p><p><a href="${escapeHtml(taskUrl)}">Ouvrir la tâche dans N09 - Suivi des tâches</a></p><p>Ce message a été envoyé selon tes préférences de notification NSK Tech 09.</p>`,
          tags: ["n09-task-notification"],
        }),
      });
      if (!response.ok) throw Object.assign(new Error("notification_email_provider_failed"), {
        code: response.status === 429 || response.status >= 500 ? "notification_email_provider_retryable" : "notification_email_provider_rejected",
      });
    },
  });
}

function safeErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code : "notification_email_delivery_failed";
  return ERROR_CODE.test(code) ? code : "notification_email_delivery_failed";
}

export async function consumeNotificationEmailDeliveries({
  repository, delivery, workerId, limit, maxAttempts, leaseMs, retryBaseMs, notBefore, now = () => new Date(),
}) {
  if (!repository || !delivery || typeof delivery.send !== "function" || !WORKER_ID.test(workerId)) {
    throw new Error("invalid notification email worker");
  }
  const claimedAt = now();
  const claimed = await repository.claimNotificationEmailDeliveries({ workerId, limit, now: claimedAt, leaseMs, notBefore });
  const outcome = { claimed: claimed.length, processed: 0, retried: 0, quarantined: 0 };
  for (const item of claimed) {
    try {
      await delivery.send(item);
      const deliveredAt = now();
      await repository.completeNotificationEmailDelivery({
        deliveryId: item.deliveryId, workerId, deliveredAt,
        auditEvent: createAuditEvent({
          action: "notification.email_delivered", result: "success", source: "notification-email-worker",
          correlationId: randomUUID(), subjectId: item.recipientIdentityId,
          newValue: { delivery_id: item.deliveryId, notification_id: item.notificationId, delivered_at: deliveredAt.toISOString() },
        }),
      });
      outcome.processed += 1;
    } catch (error) {
      const quarantined = item.processingAttempts >= maxAttempts || error?.code === "notification_email_provider_rejected";
      const failedAt = now();
      const availableAt = new Date(failedAt.valueOf() + retryBaseMs * (2 ** Math.max(0, item.processingAttempts - 1)));
      const errorCode = safeErrorCode(error);
      await repository.failNotificationEmailDelivery({
        deliveryId: item.deliveryId, workerId, availableAt, errorCode, quarantined,
        auditEvent: createAuditEvent({
          action: quarantined ? "notification.email_quarantined" : "notification.email_retry_scheduled",
          result: quarantined ? "failure" : "pending", source: "notification-email-worker",
          correlationId: randomUUID(), subjectId: item.recipientIdentityId,
          newValue: { delivery_id: item.deliveryId, notification_id: item.notificationId, error_code: errorCode,
            available_at: quarantined ? null : availableAt.toISOString() },
        }),
      });
      if (quarantined) outcome.quarantined += 1;
      else outcome.retried += 1;
    }
  }
  return Object.freeze(outcome);
}
