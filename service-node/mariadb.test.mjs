import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import {
  createApplicationSession, createApplicationSessionAuditEvent, revokeApplicationSession,
} from "./application-session.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import {
  acquireNotificationProcessingLock, createMariaDbPool, MariaDbRepository,
} from "./mariadb.mjs";
import { prepareApplicationAccessCatalog } from "./application-access-catalog.mjs";

const identity = { identityId: "identity-1", email: "COLLEGUE@example.test", displayName: "Collègue", status: "active" };
const audit = (changes = {}) => createAuditEvent({
  action: "identity.created", result: "success", source: "tests", correlationId: "correlation-1",
  subjectId: "identity-1", eventId: "event-1", occurredAt: new Date("2026-08-10T06:00:00Z"), ...changes,
});

function fakePool({ failAudit = false } = {}) {
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"),
    commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"),
    release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT identity_id")) return [[]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      if (failAudit && sql.includes("INSERT INTO audit_events")) throw new Error("audit unavailable");
      return [{ affectedRows: 1 }];
    },
  };
  return { calls, getConnection: async () => connection };
}

test("refuse une configuration MariaDB incomplète", async () => {
  await assert.rejects(createMariaDbPool({ host: "db", user: "n09", password: "secret" }), /database/);
});

test("valide écriture métier et audit dans une seule transaction", async () => {
  const pool = fakePool();
  await new MariaDbRepository(pool).saveIdentity(identity, audit());
  assert.equal(pool.calls[0], "begin");
  assert.equal(pool.calls.at(-2), "commit");
  assert.equal(pool.calls.at(-1), "release");
  assert.equal(pool.calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
});

test("annule l’écriture métier si l’audit échoue", async () => {
  const pool = fakePool({ failAudit: true });
  await assert.rejects(new MariaDbRepository(pool).saveIdentity(identity, audit()), /audit unavailable/);
  assert.equal(pool.calls.at(-2), "rollback");
  assert.equal(pool.calls.at(-1), "release");
  assert.equal(pool.calls.includes("commit"), false);
});

test("refuse un contexte d’audit incohérent avant d’ouvrir une transaction", async () => {
  const pool = fakePool();
  await assert.rejects(new MariaDbRepository(pool).saveIdentity(identity, audit({ subjectId: "identity-2" })), /must match/);
  assert.equal(pool.calls.length, 0);
});

test("persiste la demande de rattachement et son audit dans la même transaction", async () => {
  const pool = fakePool();
  const requestedAt = new Date("2026-08-10T09:00:00Z");
  const request = createLinkRequest({
    issuer: "https://login.infomaniak.com", subject: "external-42",
    providerKey: "infomaniak", now: requestedAt,
  });
  const event = createAuditEvent({
    action: "external_identity.link_requested", result: "pending",
    source: "tests", correlationId: "correlation-link", occurredAt: requestedAt,
  });
  await new MariaDbRepository(pool).saveLinkRequest(request, event);
  assert.equal(pool.calls[0], "begin");
  assert.equal(pool.calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO external_identity_link_requests")), true);
  assert.equal(pool.calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(pool.calls.at(-2), "commit");
});

test("persiste une version de catalogue et son audit dans la même transaction", async () => {
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"),
    commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"),
    release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM applications") && sql.includes("FOR UPDATE")) return [[{ application_id: "tasks" }]];
      if (sql.includes("FROM application_access_catalog_versions")) return [[]];
      if (sql.includes("FROM access_assignments")) return [[]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  const pool = { getConnection: async () => connection };
  const catalog = prepareApplicationAccessCatalog({
    application_id: "tasks", catalog_version: 1,
    permissions: [{ permission_id: "tasks:read", display_name: "Lire", description: "Consulter les tâches.", status: "active" }],
    scope_types: [{ scope_type_id: "global", display_name: "Global", description: "Toute l’application.", status: "active" }],
    roles: [{ role_id: "tasks-reader", display_name: "Lecteur", description: "Lecture globale.", status: "active", permissions: ["tasks:read"], scope_types: ["global"] }],
    provisioning: { mode: "central_identity_only", identity_key: "identity_id", readiness: "immediate", automatic_profile_creation: false, email_matching: "forbidden", requirements: [] },
  });
  const event = createAuditEvent({
    action: "application.access_catalog_published", result: "success", source: "tests",
    correlationId: "catalog-correlation", applicationId: "tasks",
  });
  const result = await new MariaDbRepository(pool).publishApplicationAccessCatalog(catalog, event);
  assert.equal(result.created, true);
  assert.equal(calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO application_access_catalog_versions")), true);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(calls.at(-2), "commit");
  assert.equal(calls.at(-1), "release");
});

function notificationMaterializationInput(resolutionHash = "b".repeat(64)) {
  const event = {
    sourceApplicationId: "n09-suivi-taches", eventId: "event_abcdef0123456789abcd",
    eventHash: "a".repeat(64), occurredAt: "2026-08-12T10:00:00.000Z",
  };
  const createdAt = new Date("2026-08-12T10:02:00.000Z");
  return {
    event, policyVersion: "tasks-notification-policy-v1", resolutionHash,
    suppressed: { own_action: 0, preferences: 0, unlinked_identity: 0 },
    notifications: [{
      notificationId: "c".repeat(64), recipientIdentityId: "00000000-0000-4000-8000-000000000001",
      category: "task_activity", importance: "information", title: "Tâche archivée",
      message: "Une tâche a été archivée.", contextApplicationId: "n09-suivi-taches",
      contextResourceType: "task", contextResourceId: "task_1",
      occurredAt: event.occurredAt, createdAt,
    }],
    externalDeliveries: [{
      deliveryId: "d".repeat(64), notificationId: "c".repeat(64), channel: "email",
      status: "blocked", blockedReason: "channel_not_enabled", createdAt,
    }],
    resolvedAt: createdAt,
    auditEvent: createAuditEvent({
      action: "notification.event_materialized", result: "success", source: "tests",
      correlationId: "notification-correlation", applicationId: "n09-suivi-taches",
      newValue: { source_event_id: event.eventId, resolution_hash: resolutionHash },
    }),
  };
}

test("matérialise résolution, notification, blocage externe et audit dans une transaction", async () => {
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM notification_resolutions")) return [[]];
      if (sql.includes("FROM notification_events")) return [[{ event_hash: "a".repeat(64), status: "processing" }]];
      if (sql.includes("FROM identities WHERE status = 'active'")) {
        return [[{ identity_id: "00000000-0000-4000-8000-000000000001" }]];
      }
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  const repository = new MariaDbRepository({ getConnection: async () => connection });
  const result = await repository.materializeNotificationResolution(notificationMaterializationInput());
  assert.deepEqual(result, { created: true, notifications: 1, externalDeliveriesBlocked: 1 });
  assert.ok(calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO notification_resolutions")));
  assert.ok(calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO notifications")));
  assert.ok(calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO notification_external_deliveries")));
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(calls.at(-2), "commit");
});

test("reconnaît une résolution identique et refuse toute dérive", async () => {
  const pool = (storedHash) => {
    const calls = [];
    const connection = {
      beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
      rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
      execute: async (sql, values = []) => {
        calls.push({ sql, values });
        if (sql.includes("FROM notification_resolutions")) return [[{
          resolution_hash: storedHash, internal_notification_count: 1, blocked_external_delivery_count: 1,
        }]];
        throw new Error("no write expected");
      },
    };
    return { calls, getConnection: async () => connection };
  };
  const same = pool("b".repeat(64));
  const result = await new MariaDbRepository(same).materializeNotificationResolution(notificationMaterializationInput());
  assert.deepEqual(result, { created: false, notifications: 1, externalDeliveriesBlocked: 1 });
  assert.equal(same.calls.includes("commit"), true);
  const conflict = pool("e".repeat(64));
  await assert.rejects(
    new MariaDbRepository(conflict).materializeNotificationResolution(notificationMaterializationInput()),
    (error) => error.code === "notification_resolution_conflict",
  );
  assert.equal(conflict.calls.includes("rollback"), true);
});

test("agrège l’exploitation des notifications sans exposer leur contenu", async () => {
  const calls = [];
  const pool = {
    execute: async (sql) => {
      calls.push(sql);
      if (sql.includes("FROM notification_events")) return [[{
        total: 5, pending: 1, processing: 1, retrying: 1, processed: 2, quarantined: 0,
        oldest_available_at: new Date("2026-08-12T08:00:00.000Z"),
        last_received_at: new Date("2026-08-12T08:01:00.000Z"),
        last_processed_at: new Date("2026-08-12T08:02:00.000Z"),
      }]];
      if (sql.includes("FROM notifications")) return [[{ total: 2, unread: 1, archived: 0 }]];
      if (sql.includes("FROM notification_external_deliveries")) return [[{
        total: 2, blocked: 2, non_blocked: 0, pending: 0, processing: 0,
        retrying: 0, delivered: 0, quarantined: 0,
      }]];
      if (sql.includes("JSON_EXTRACT")) return [[{ own_action: 2, preferences: 1, unlinked_identity: 3 }]];
      if (sql.includes("ORDER BY resolved_at DESC")) return [[{
        source_application_id: "n09-suivi-taches", source_event_id: "event_1",
        policy_version: "tasks-notification-policy-v1",
        suppressed_json: JSON.stringify({ own_action: 1, preferences: 0, unlinked_identity: 0 }),
        internal_notification_count: 1, blocked_external_delivery_count: 2,
        resolved_at: new Date("2026-08-12T08:02:00.000Z"),
      }]];
      if (sql.includes("FROM notification_processing_state")) return [[{
        last_started_at: new Date("2026-08-12T08:01:59.000Z"),
        last_finished_at: new Date("2026-08-12T08:02:00.000Z"),
        last_status: "succeeded", last_error_code: null, last_claimed: 2,
        last_processed: 2, last_retried: 0, last_quarantined: 0, version: 4,
      }]];
      throw new Error("unexpected query");
    },
  };
  const snapshot = await new MariaDbRepository(pool).getNotificationOperationsSnapshot(20);
  assert.equal(snapshot.events.pending, 1);
  assert.equal(snapshot.events.retrying, 1);
  assert.equal(snapshot.notifications.unread, 1);
  assert.equal(snapshot.externalDeliveries.nonBlocked, 0);
  assert.deepEqual(snapshot.processor, {
    status: "succeeded", lastStartedAt: "2026-08-12T08:01:59.000Z",
    lastFinishedAt: "2026-08-12T08:02:00.000Z", errorCode: null,
    claimed: 2, processed: 2, retried: 0, quarantined: 0, version: 4,
  });
  assert.deepEqual(snapshot.suppressions, { ownAction: 2, preferences: 1, unlinkedIdentity: 3 });
  assert.equal(snapshot.recentResolutions[0].eventId, "event_1");
  assert.deepEqual(snapshot.recentResolutions[0].suppressed, {
    own_action: 1, preferences: 0, unlinked_identity: 0,
  });
  assert.equal(calls.some((sql) => /title|message|email|payload_json/i.test(sql)), false);
  await assert.rejects(new MariaDbRepository(pool).getNotificationOperationsSnapshot(101), /invalid/);
});

test("conserve uniquement le dernier état borné du consommateur", async () => {
  const calls = [];
  const repository = new MariaDbRepository({ execute: async (sql, values) => {
    calls.push({ sql, values }); return [{ affectedRows: 1 }];
  } });
  await repository.recordNotificationProcessingRun({
    status: "succeeded", startedAt: new Date("2026-08-12T10:00:00Z"),
    finishedAt: new Date("2026-08-12T10:00:01Z"), errorCode: null,
    claimed: 2, processed: 2, retried: 0, quarantined: 0,
  });
  assert.match(calls[0].sql, /ON DUPLICATE KEY UPDATE/);
  assert.doesNotMatch(calls[0].sql, /worker|payload|title|message|email/i);
  await assert.rejects(repository.recordNotificationProcessingRun({
    status: "failed", startedAt: new Date(), finishedAt: new Date(), errorCode: "secret value",
    claimed: 0, processed: 0, retried: 0, quarantined: 0,
  }), /invalid/);
});

test("acquiert et libère un verrou MariaDB non bloquant", async () => {
  const calls = [];
  const connection = {
    execute: async (sql, values) => {
      calls.push({ sql, values });
      return sql.includes("GET_LOCK") ? [[{ acquired: 1 }]] : [[{ released: 1 }]];
    },
    release: () => calls.push("release"),
  };
  const lock = await acquireNotificationProcessingLock({ getConnection: async () => connection });
  assert.ok(lock);
  await lock.release();
  await lock.release();
  assert.equal(calls.filter((call) => call === "release").length, 1);
  assert.match(calls[0].sql, /GET_LOCK\(\?, 0\)/);
  assert.match(calls[1].sql, /RELEASE_LOCK/);
});

test("abandonne proprement un cycle déjà verrouillé", async () => {
  let released = 0;
  const connection = {
    execute: async () => [[{ acquired: 0 }]], release: () => { released += 1; },
  };
  assert.equal(await acquireNotificationProcessingLock({ getConnection: async () => connection }), null);
  assert.equal(released, 1);
});

function persistedSession() {
  return createApplicationSession({
    identityId: "identity-1", applicationId: "tasks",
    idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: new Date("2026-08-13T04:00:00Z"), now: new Date("2026-08-13T04:01:00Z"),
    randomUuidImpl: () => "00000000-0000-4000-8000-000000000044",
    randomBytesImpl: () => Buffer.alloc(32, 11),
  }).record;
}

function sessionRow(record) {
  return {
    session_id: record.sessionId, secret_hash: record.secretHash,
    identity_id: record.identityId, application_id: record.applicationId,
    issued_at: record.issuedAt, last_seen_at: record.lastSeenAt,
    idle_expires_at: record.idleExpiresAt, absolute_expires_at: record.absoluteExpiresAt,
    authenticated_at: record.authenticatedAt, idle_ttl_ms: record.idleTtlMs,
    context_label: record.contextLabel, revoked_at: record.revokedAt,
    revoked_by_identity_id: record.revokedByIdentityId,
    revocation_reason: record.revocationReason, version: record.version,
  };
}

test("persiste une session et son audit MariaDB dans la même transaction", async () => {
  const pool = fakePool();
  const record = persistedSession();
  const event = createApplicationSessionAuditEvent({
    record, action: "application_session.created", correlationId: "session-created",
  });
  await new MariaDbRepository(pool).saveApplicationSession(record, event);
  assert.ok(pool.calls.some((call) => typeof call === "object" && call.sql.includes("INSERT INTO application_sessions")));
  assert.equal(pool.calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(pool.calls.at(-2), "commit");
  assert.equal(pool.calls.at(-1), "release");
});

test("annule la création de session si son audit MariaDB échoue", async () => {
  const pool = fakePool({ failAudit: true });
  const record = persistedSession();
  const event = createApplicationSessionAuditEvent({
    record, action: "application_session.created", correlationId: "session-created",
  });
  await assert.rejects(new MariaDbRepository(pool).saveApplicationSession(record, event), /audit unavailable/);
  assert.equal(pool.calls.at(-2), "rollback");
  assert.equal(pool.calls.at(-1), "release");
  assert.equal(pool.calls.includes("commit"), false);
});

test("lit le registre complet des sessions en une seule requête ordonnée", async () => {
  const record = persistedSession();
  const calls = [];
  const repository = new MariaDbRepository({
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      return [[sessionRow(record)]];
    },
  });
  assert.deepEqual(await repository.listAllApplicationSessions(), [record]);
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /ORDER BY last_seen_at DESC, session_id/);
  assert.deepEqual(calls[0].values, []);
});

test("actualise l’activité MariaDB seulement pour la version active attendue", async () => {
  const calls = [];
  const active = persistedSession();
  let updateAffectedRows = 1;
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM application_sessions") && sql.includes("FOR UPDATE")) return [[sessionRow(active)]];
      return [{ affectedRows: updateAffectedRows }];
    },
  };
  const pool = { getConnection: async () => connection };
  const record = { ...active, lastSeenAt: "2026-08-13T04:30:00.000Z", idleExpiresAt: "2026-08-13T05:30:00.000Z", version: 2 };
  await new MariaDbRepository(pool).touchApplicationSession(record, 1);
  const update = calls.find((call) => typeof call === "object" && call.sql.includes("UPDATE application_sessions"));
  assert.match(update.sql, /version = \? AND revoked_at IS NULL/);
  assert.match(update.sql, /absolute_expires_at > \? AND idle_expires_at > \?/);
  assert.equal(calls.at(-2), "commit");

  updateAffectedRows = 0;
  await assert.rejects(new MariaDbRepository(pool).touchApplicationSession(record, 1), /stale or inactive/);
  assert.equal(calls.at(-2), "rollback");
});

test("révoque une session MariaDB avec verrou, version et audit atomique", async () => {
  const active = persistedSession();
  const revoked = revokeApplicationSession(active, {
    revokedByIdentityId: active.identityId, reason: "Déconnexion distante demandée",
    now: new Date("2026-08-13T04:20:00Z"),
  });
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM application_sessions") && sql.includes("FOR UPDATE")) return [[sessionRow(active)]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  const event = createApplicationSessionAuditEvent({
    record: revoked, action: "application_session.revoked", actorId: active.identityId,
    correlationId: "session-revoked",
  });
  await new MariaDbRepository({ getConnection: async () => connection }).revokeApplicationSession(revoked, 1, event);
  assert.ok(calls.some((call) => typeof call === "object" && call.sql.includes("SET revoked_at")));
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(calls.at(-2), "commit");
});

test("verrouille et révoque un groupe de sessions dans une seule transaction", async () => {
  const first = persistedSession();
  const second = createApplicationSession({
    identityId: first.identityId, applicationId: first.applicationId,
    idleTtlMs: 60 * 60_000, absoluteTtlMs: 4 * 60 * 60_000,
    authenticatedAt: new Date("2026-08-13T04:02:00Z"), now: new Date("2026-08-13T04:02:00Z"),
    randomUuidImpl: () => "00000000-0000-4000-8000-000000000045",
    randomBytesImpl: () => Buffer.alloc(32, 12),
  }).record;
  const active = new Map([[first.sessionId, first], [second.sessionId, second]]);
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.includes("FROM application_sessions") && sql.includes("FOR UPDATE")) {
        return [[sessionRow(active.get(values[0]))]];
      }
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  const closures = [second, first].map((record, index) => {
    const revoked = revokeApplicationSession(record, {
      revokedByIdentityId: record.identityId, reason: "Fermeture groupée demandée",
      now: new Date("2026-08-13T04:20:00Z"),
    });
    return {
      record: revoked, expectedVersion: record.version,
      auditEvent: createApplicationSessionAuditEvent({
        record: revoked, action: "application_session.revoked", actorId: record.identityId,
        correlationId: `batch-session-${index}`,
      }),
    };
  });
  await new MariaDbRepository({ getConnection: async () => connection }).revokeApplicationSessions(closures);
  const lockedIds = calls
    .filter((call) => typeof call === "object" && call.sql.includes("FROM application_sessions") && call.sql.includes("FOR UPDATE"))
    .map((call) => call.values[0]);
  assert.deepEqual(lockedIds, [first.sessionId, second.sessionId]);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("SET revoked_at")).length, 2);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 2);
  assert.equal(calls.filter((call) => call === "begin").length, 1);
  assert.equal(calls.filter((call) => call === "commit").length, 1);
  assert.equal(calls.at(-1), "release");
});

test("suspend l’identité et révoque ses sessions MariaDB dans une transaction unique", async () => {
  const active = persistedSession();
  const suspended = { ...identity, status: "suspended" };
  const revoked = revokeApplicationSession(active, {
    revokedByIdentityId: identity.identityId,
    reason: "Suspension gouvernée après contrôle humain",
    now: new Date("2026-08-13T04:20:00Z"),
  });
  const correlationId = "identity-suspension-atomic";
  const identityAuditEvent = createAuditEvent({
    action: "identity.suspended", result: "success", source: "tests", correlationId,
    actorId: identity.identityId, subjectId: identity.identityId,
    previousValue: { status: "active" }, newValue: { status: "suspended", revoked_sessions: 1 },
    justification: "Suspension gouvernée après contrôle humain",
  });
  const sessionAuditEvent = createApplicationSessionAuditEvent({
    record: revoked, action: "application_session.revoked", actorId: identity.identityId,
    correlationId, justification: "Suspension gouvernée après contrôle humain",
  });
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT status FROM identities")) return [[{ status: "active" }]];
      if (sql.includes("FROM application_sessions") && sql.includes("FOR UPDATE")) return [[sessionRow(active)]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  await new MariaDbRepository({ getConnection: async () => connection }).suspendIdentityAndRevokeSessions({
    identity: suspended, expectedStatus: "active", observedAt: new Date("2026-08-13T04:20:00Z"), identityAuditEvent,
    closures: [{ record: revoked, expectedVersion: active.version, auditEvent: sessionAuditEvent }],
  });
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("UPDATE identities SET status = 'suspended'")).length, 1);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("SET revoked_at")).length, 1);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 2);
  assert.equal(calls.filter((call) => call === "begin").length, 1);
  assert.equal(calls.filter((call) => call === "commit").length, 1);
  assert.equal(calls.at(-1), "release");
});

test("réactive l’identité MariaDB sans restaurer de session et avec audit atomique", async () => {
  const reactivated = { ...identity, status: "active" };
  const identityAuditEvent = createAuditEvent({
    action: "identity.reactivated", result: "success", source: "tests",
    correlationId: "identity-reactivation-atomic", actorId: identity.identityId,
    subjectId: identity.identityId, previousValue: { status: "suspended" },
    newValue: { status: "active", active_sessions: 0, restored_sessions: 0 },
    justification: "Réactivation gouvernée après nouvelle décision humaine",
  });
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT status FROM identities")) return [[{ status: "suspended" }]];
      if (sql.includes("SELECT session_id FROM application_sessions")) return [[]];
      if (sql.startsWith("SELECT current_hash")) return [[{ current_hash: "" }]];
      return [{ affectedRows: 1 }];
    },
  };
  await new MariaDbRepository({ getConnection: async () => connection }).reactivateIdentity({
    identity: reactivated, expectedStatus: "suspended",
    observedAt: new Date("2026-08-13T05:00:00Z"), identityAuditEvent,
  });
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("UPDATE identities SET status = 'active'")).length, 1);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("SET revoked_at")).length, 0);
  assert.equal(calls.filter((call) => typeof call === "object" && call.sql.includes("INSERT INTO audit_events")).length, 1);
  assert.equal(calls.filter((call) => call === "begin").length, 1);
  assert.equal(calls.filter((call) => call === "commit").length, 1);
  assert.equal(calls.at(-1), "release");
});

test("annule la réactivation MariaDB si une session active subsiste", async () => {
  const identityAuditEvent = createAuditEvent({
    action: "identity.reactivated", result: "success", source: "tests",
    correlationId: "identity-reactivation-rejected", actorId: identity.identityId,
    subjectId: identity.identityId, previousValue: { status: "suspended" },
    newValue: { status: "active", active_sessions: 0, restored_sessions: 0 },
    justification: "Réactivation refusée car une session active subsiste",
  });
  const calls = [];
  const connection = {
    beginTransaction: async () => calls.push("begin"), commit: async () => calls.push("commit"),
    rollback: async () => calls.push("rollback"), release: () => calls.push("release"),
    execute: async (sql, values = []) => {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT status FROM identities")) return [[{ status: "suspended" }]];
      if (sql.includes("SELECT session_id FROM application_sessions")) return [[{ session_id: "still-active" }]];
      return [{ affectedRows: 1 }];
    },
  };
  await assert.rejects(new MariaDbRepository({ getConnection: async () => connection }).reactivateIdentity({
    identity: { ...identity, status: "active" }, expectedStatus: "suspended",
    observedAt: new Date("2026-08-13T05:00:00Z"), identityAuditEvent,
  }), /still has active sessions/);
  assert.equal(calls.includes("rollback"), true);
  assert.equal(calls.some((call) => typeof call === "object" && call.sql.includes("UPDATE identities")), false);
  assert.equal(calls.at(-1), "release");
});
