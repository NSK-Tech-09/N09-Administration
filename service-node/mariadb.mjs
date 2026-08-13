import { createHash, randomUUID } from "node:crypto";
import { canonicalJson, eventHash, verifyAuditChain } from "./audit.mjs";
import {
  assertApplicationSessionActivityProgress,
  assertApplicationSessionAudit,
  assertApplicationSessionImmutableContext,
  assertNewApplicationSessionRecord,
} from "./application-session.mjs";
import { externalPrincipalKey } from "./federated-identity.mjs";
import {
  ApplicationAccessCatalogError, applicationAccessCatalogHash, assertCompatibleCatalogEvolution,
} from "./application-access-catalog.mjs";
import { NotificationIngressError } from "./notification-ingress.mjs";

function required(config, name) {
  const value = config[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`missing MariaDB setting: ${name}`);
  return value;
}

export async function createMariaDbPool(config) {
  const options = {
    host: required(config, "host"),
    user: required(config, "user"),
    password: required(config, "password"),
    database: required(config, "database"),
  };
  const { default: mysql } = await import("mysql2/promise");
  return mysql.createPool({
    ...options,
    port: Number(config.port ?? 3306),
    charset: "utf8mb4",
    timezone: "Z",
    ssl: config.ssl === false ? undefined : { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: Number(config.connectionLimit ?? 5),
    queueLimit: 0,
  });
}

export async function acquireNotificationProcessingLock(
  pool, lockName = "n09:administration:notification-processing:v1",
) {
  if (!pool || typeof pool.getConnection !== "function" ||
      typeof lockName !== "string" || !/^[A-Za-z0-9._:-]{3,64}$/.test(lockName)) {
    throw new Error("invalid notification processing lock");
  }
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.execute("SELECT GET_LOCK(?, 0) AS acquired", [lockName]);
    if (Number(rows[0]?.acquired) !== 1) {
      connection.release();
      return null;
    }
  } catch (error) {
    connection.release();
    throw error;
  }
  let released = false;
  return Object.freeze({
    release: async () => {
      if (released) return;
      released = true;
      try {
        const [rows] = await connection.execute("SELECT RELEASE_LOCK(?) AS released", [lockName]);
        if (Number(rows[0]?.released) !== 1) throw new Error("notification processing lock was lost");
      } finally {
        connection.release();
      }
    },
  });
}

function asMariaDate(value) {
  if (!value) return null;
  return new Date(value).toISOString().replace("T", " ").replace("Z", "");
}

function parseJson(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function asIso(value) {
  return value ? new Date(value).toISOString() : null;
}

function mapLinkRequest(row) {
  if (!row) return null;
  return {
    requestId: row.request_id, issuer: row.issuer, subject: row.subject,
    providerKey: row.provider_key, emailHint: row.email_hint,
    displayNameHint: row.display_name_hint, requestedAt: asIso(row.requested_at),
    expiresAt: asIso(row.expires_at), status: row.status,
    targetIdentityId: row.target_identity_id, decidedBy: row.decided_by,
    decisionJustification: row.decision_justification,
  };
}

function mapApplicationAccessCatalog(row) {
  if (!row) return null;
  return {
    applicationId: row.application_id, catalogVersion: Number(row.catalog_version),
    catalogHash: row.catalog_hash, roles: parseJson(row.roles_json),
    permissions: parseJson(row.permissions_json), scopeTypes: parseJson(row.scope_types_json),
    provisioning: parseJson(row.provisioning_json), publishedAt: asIso(row.published_at),
  };
}

function mapNotificationEvent(row) {
  if (!row) return null;
  return {
    sourceApplicationId: row.source_application_id, eventId: row.source_event_id,
    eventType: row.event_type, eventHash: row.event_hash, taskId: row.task_id,
    siteId: row.site_id, actorId: row.actor_id, aggregateId: row.aggregate_id,
    payload: parseJson(row.payload_json), occurredAt: asIso(row.occurred_at),
    receivedAt: asIso(row.received_at), status: row.status,
    processingAttempts: Number(row.processing_attempts), availableAt: asIso(row.available_at),
    claimedAt: asIso(row.claimed_at), claimedBy: row.claimed_by,
    processedAt: asIso(row.processed_at), lastErrorCode: row.last_error_code,
  };
}

function mapApplicationSession(row) {
  if (!row) return null;
  return {
    sessionId: row.session_id, secretHash: row.secret_hash,
    identityId: row.identity_id, applicationId: row.application_id,
    issuedAt: asIso(row.issued_at), lastSeenAt: asIso(row.last_seen_at),
    idleExpiresAt: asIso(row.idle_expires_at), absoluteExpiresAt: asIso(row.absolute_expires_at),
    authenticatedAt: asIso(row.authenticated_at), idleTtlMs: Number(row.idle_ttl_ms),
    contextLabel: row.context_label, revokedAt: asIso(row.revoked_at),
    revokedByIdentityId: row.revoked_by_identity_id,
    revocationReason: row.revocation_reason, version: Number(row.version),
  };
}

export class MariaDbRepository {
  constructor(pool) {
    this.pool = pool;
  }

  async #transaction(operation) {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await operation(connection);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async #appendAudit(connection, event) {
    const [rows] = await connection.execute(
      "SELECT current_hash FROM audit_chain_head WHERE chain_id = 1 FOR UPDATE",
    );
    if (rows.length !== 1) throw new Error("audit chain head is missing");
    const previousHash = rows[0].current_hash;
    const hash = eventHash(event, previousHash);
    await connection.execute(
      `INSERT INTO audit_events(
         event_id, correlation_id, occurred_at, action, result, source,
         event_payload_json, previous_hash, event_hash
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [event.event_id, event.correlation_id, asMariaDate(event.occurred_at), event.action,
       event.result, event.source, canonicalJson(event), previousHash, hash],
    );
    await connection.execute(
      "UPDATE audit_chain_head SET current_hash = ?, last_sequence = LAST_INSERT_ID() WHERE chain_id = 1",
      [hash],
    );
  }

  async saveIdentity(identity, auditEvent) {
    if (auditEvent.subject_id !== identity.identityId) throw new Error("audit subject must match identity");
    return this.#transaction(async (connection) => {
      const [existing] = await connection.execute(
        "SELECT identity_id FROM identities WHERE identity_id = ? FOR UPDATE", [identity.identityId],
      );
      if (existing.length && !auditEvent.previous_value) throw new Error("previous value is required for update");
      const email = identity.email.trim().toLowerCase();
      await connection.execute(
        `INSERT INTO identities(identity_id, email, email_normalized, display_name, status)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE email = VALUES(email), email_normalized = VALUES(email_normalized),
           display_name = VALUES(display_name), status = VALUES(status)`,
        [identity.identityId, email, email, identity.displayName.trim(), identity.status],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async saveApplication(application, auditEvent) {
    if (auditEvent.application_id !== application.applicationId) throw new Error("audit application must match application");
    return this.#transaction(async (connection) => {
      const [existing] = await connection.execute(
        "SELECT application_id FROM applications WHERE application_id = ? FOR UPDATE", [application.applicationId],
      );
      if (existing.length && !auditEvent.previous_value) throw new Error("previous value is required for update");
      await connection.execute(
        `INSERT INTO applications(application_id, display_name, status, registration_policy)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE display_name = VALUES(display_name), status = VALUES(status),
           registration_policy = VALUES(registration_policy)`,
        [application.applicationId, application.displayName.trim(), application.status, application.registrationPolicy],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async saveLinkRequest(request, auditEvent) {
    if (request.status !== "pending") throw new Error("a new link request must be pending");
    if (auditEvent.action !== "external_identity.link_requested") throw new Error("invalid audit action for link request");
    return this.#transaction(async (connection) => {
      const [linked] = await connection.execute(
        "SELECT 1 FROM external_identities WHERE issuer = ? AND subject = ? FOR UPDATE",
        [request.issuer, request.subject],
      );
      if (linked.length) throw new Error("external identity is already linked");
      const [pending] = await connection.execute(
        `SELECT request_id FROM external_identity_link_requests
         WHERE issuer = ? AND subject = ? AND status = 'pending' AND expires_at > ?
         FOR UPDATE`,
        [request.issuer, request.subject, asMariaDate(request.requestedAt)],
      );
      if (pending.length) throw new Error("an active link request already exists");
      await connection.execute(
        `INSERT INTO external_identity_link_requests(
           request_id, issuer, subject, provider_key, email_hint, display_name_hint,
           requested_at, expires_at, status, target_identity_id, decided_by, decision_justification
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, '')`,
        [request.requestId, request.issuer, request.subject, request.providerKey,
         request.emailHint, request.displayNameHint, asMariaDate(request.requestedAt),
         asMariaDate(request.expiresAt)],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async getLinkRequest(requestId) {
    const [rows] = await this.pool.execute(
      "SELECT * FROM external_identity_link_requests WHERE request_id = ?", [requestId],
    );
    return mapLinkRequest(rows[0]);
  }

  async publishApplicationAccessCatalog(catalog, auditEvent) {
    if (auditEvent.application_id !== catalog.applicationId) throw new Error("audit application must match catalog");
    return this.#transaction(async (connection) => {
      const [applications] = await connection.execute(
        "SELECT application_id FROM applications WHERE application_id = ? FOR UPDATE", [catalog.applicationId],
      );
      if (!applications.length) throw new Error("application not found");
      const [versions] = await connection.execute(
        `SELECT * FROM application_access_catalog_versions
         WHERE application_id = ? ORDER BY catalog_version DESC FOR UPDATE`, [catalog.applicationId],
      );
      const catalogHash = applicationAccessCatalogHash(catalog);
      const sameVersion = versions.find((row) => Number(row.catalog_version) === catalog.catalogVersion);
      if (sameVersion) {
        if (sameVersion.catalog_hash !== catalogHash) throw new ApplicationAccessCatalogError("catalog_version_conflict", 409);
        return { created: false, catalog: mapApplicationAccessCatalog(sameVersion) };
      }
      const previous = mapApplicationAccessCatalog(versions[0]);
      assertCompatibleCatalogEvolution(previous, catalog);
      const [assignmentRows] = await connection.execute(
        `SELECT role_id, permissions_json FROM access_assignments
         WHERE application_id = ? AND status = 'active' FOR UPDATE`, [catalog.applicationId],
      );
      const roleIds = new Set(catalog.roles.map((item) => item.role_id));
      const permissionIds = new Set(catalog.permissions.map((item) => item.permission_id));
      if (assignmentRows.some((row) => !roleIds.has(row.role_id) || parseJson(row.permissions_json).some((item) => !permissionIds.has(item)))) {
        throw new ApplicationAccessCatalogError("catalog_excludes_active_assignment", 409);
      }
      await connection.execute(
        `INSERT INTO application_access_catalog_versions(
           application_id, catalog_version, catalog_hash, roles_json, permissions_json,
           scope_types_json, provisioning_json, published_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [catalog.applicationId, catalog.catalogVersion, catalogHash, JSON.stringify(catalog.roles),
         JSON.stringify(catalog.permissions), JSON.stringify(catalog.scopeTypes),
         JSON.stringify(catalog.provisioning), asMariaDate(auditEvent.occurred_at)],
      );
      await this.#appendAudit(connection, auditEvent);
      return {
        created: true,
        catalog: { ...structuredClone(catalog), catalogHash, publishedAt: auditEvent.occurred_at },
      };
    });
  }

  async listLinkRequests(status = null) {
    const [rows] = status
      ? await this.pool.execute(
        "SELECT * FROM external_identity_link_requests WHERE status = ? ORDER BY requested_at DESC", [status],
      )
      : await this.pool.execute(
        "SELECT * FROM external_identity_link_requests ORDER BY requested_at DESC",
      );
    return rows.map(mapLinkRequest);
  }

  async findActiveLinkRequest(issuer, subject, now = new Date()) {
    const [rows] = await this.pool.execute(
      `SELECT * FROM external_identity_link_requests
       WHERE issuer = ? AND subject = ? AND status = 'pending' AND expires_at > ?
       ORDER BY requested_at DESC LIMIT 1`,
      [issuer, subject, asMariaDate(now)],
    );
    return mapLinkRequest(rows[0]);
  }

  async findExternalIdentity(issuer, subject) {
    const [rows] = await this.pool.execute(
      `SELECT external_identity_id, identity_id, issuer, subject, provider_key, status, linked_at
       FROM external_identities WHERE issuer = ? AND subject = ?`, [issuer, subject],
    );
    const row = rows[0];
    return row ? {
      externalIdentityId: row.external_identity_id, identityId: row.identity_id,
      issuer: row.issuer, subject: row.subject, providerKey: row.provider_key,
      status: row.status, linkedAt: asIso(row.linked_at),
    } : null;
  }

  async approveLinkRequest(requestId, identityId, decidedBy, justification, auditEvent, now = new Date()) {
    if (!String(justification ?? "").trim()) throw new Error("approval justification is required");
    if (auditEvent.action !== "external_identity.link_approved") throw new Error("invalid audit action for link approval");
    if (auditEvent.actor_id !== decidedBy || auditEvent.subject_id !== identityId) throw new Error("audit identities must match approval");
    return this.#transaction(async (connection) => {
      const [requests] = await connection.execute(
        "SELECT * FROM external_identity_link_requests WHERE request_id = ? FOR UPDATE", [requestï®|¶‰žËkºwµçL¹Á½½°¹•á•ÕÑ” (€€€€€M1P€¨I=4¹½Ñ¥™¥…Ñ¥½¹}•Ù•¹ÑÌ(€€€€€€]!IÍ½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥€ô€ü9Í½ÕÉ•}•Ù•¹Ñ}¥€ô€ý€°(€€€€€mÍ½ÕÉ•ÁÁ±¥…Ñ¥½¹%°•Ù•¹Ñ%‘t°(€€€€¤ì(€€€É•ÑÕÉ¸µ…Á9½Ñ¥™¥…Ñ¥½¹Ù•¹Ð¡É½ÝÍlÁt¤ì(€ô((€…Íå¹Œµ…Ñ•É¥…±¥é•9½Ñ¥™¥…Ñ¥½¹I•Í½±ÕÑ¥½¸¡ì(€€€•Ù•¹Ð°Á½±¥åY•ÉÍ¥½¸°É•Í½±ÕÑ¥½¹!…Í °ÍÕÁÁÉ•ÍÍ•°¹½Ñ¥™¥…Ñ¥½¹Ì°•áÑ•É¹…±•±¥Ù•É¥•Ì°É•Í½±Ù•‘Ð°…Õ‘¥ÑÙ•¹Ð°(€ô¤ì(€€€É•ÑÕÉ¸Ñ¡¥Ì¸ÑÉ…¹Í…Ñ¥½¸¡…Íå¹Œ€¡½¹¹•Ñ¥½¸¤€ôøì(€€€€€½¹ÍÐm•á¥ÍÑ¥¹t€ô…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€M1PÉ•Í½±ÕÑ¥½¹}¡…Í °¥¹Ñ•É¹…±}¹½Ñ¥™¥…Ñ¥½¹}½Õ¹Ð°‰±½­•‘}•áÑ•É¹…±}‘•±¥Ù•Éå}½Õ¹Ð(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}É•Í½±ÕÑ¥½¹Ì(€€€€€€€€]!IÍ½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥€ô€ü9Í½ÕÉ•}•Ù•¹Ñ}¥€ô€ü=HUAQ€°(€€€€€€€m•Ù•¹Ð¹Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%°•Ù•¹Ð¹•Ù•¹Ñ%‘t°(€€€€€€¤ì(€€€€€¥˜€¡•á¥ÍÑ¥¹œ¹±•¹Ñ ¤ì(€€€€€€€¥˜€¡•á¥ÍÑ¥¹lÁt¹É•Í½±ÕÑ¥½¹}¡…Í €„ôôÉ•Í½±ÕÑ¥½¹!…Í ¤ì(€€€€€€€€€Ñ¡É½Ü=‰©•Ð¹…ÍÍ¥¸¡¹•ÜÉÉ½È ‰¹½Ñ¥™¥…Ñ¥½¸É•Í½±ÕÑ¥½¸½¹™±¥Ðˆ¤°ì½‘”è€‰¹½Ñ¥™¥…Ñ¥½¹}É•Í½±ÕÑ¥½¹}½¹™±¥Ðˆô¤ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì(€€€€€€€€€É•…Ñ•è™…±Í”°(€€€€€€€€€¹½Ñ¥™¥…Ñ¥½¹Ìè9Õµ‰•È¡•á¥ÍÑ¥¹lÁt¹¥¹Ñ•É¹…±}¹½Ñ¥™¥…Ñ¥½¹}½Õ¹Ð¤°(€€€€€€€€€•áÑ•É¹…±•±¥Ù•É¥•Í	±½­•è9Õµ‰•È¡•á¥ÍÑ¥¹lÁt¹‰±½­•‘}•áÑ•É¹…±}‘•±¥Ù•Éå}½Õ¹Ð¤°(€€€€€€€ôì(€€€€€ô(€€€€€½¹ÍÐm•Ù•¹ÑÍt€ô…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€M1P•Ù•¹Ñ}¡…Í °ÍÑ…ÑÕÌI=4¹½Ñ¥™¥…Ñ¥½¹}•Ù•¹ÑÌ(€€€€€€€€]!IÍ½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥€ô€ü9Í½ÕÉ•}•Ù•¹Ñ}¥€ô€ü=HUAQ€°(€€€€€€€m•Ù•¹Ð¹Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%°•Ù•¹Ð¹•Ù•¹Ñ%‘t°(€€€€€€¤ì(€€€€€¥˜€ …•Ù•¹ÑÌ¹±•¹Ñ ñð•Ù•¹ÑÍlÁt¹•Ù•¹Ñ}¡…Í €„ôô•Ù•¹Ð¹•Ù•¹Ñ!…Í ñð•Ù•¹ÑÍlÁt¹ÍÑ…ÑÕÌ€„ôô€‰ÁÉ½•ÍÍ¥¹œˆ¤ì(€€€€€€€Ñ¡É½Ü=‰©•Ð¹…ÍÍ¥¸¡¹•ÜÉÉ½È ‰¹½Ñ¥™¥…Ñ¥½¸•Ù•¹Ð¥Ì¹½Ð½Ý¹•™½ÈÁÉ½•ÍÍ¥¹œˆ¤°ì½‘”è€‰¹½Ñ¥™¥…Ñ¥½¹}•Ù•¹Ñ}Õ¹…Ù…¥±…‰±”ˆô¤ì(€€€€€ô(€€€€€½¹ÍÐÉ•¥Á¥•¹Ñ%‘Ì€ôl¸¸¹¹•ÜM•Ð¡¹½Ñ¥™¥…Ñ¥½¹Ì¹µ…À ¡¹½Ñ¥™¥…Ñ¥½¸¤€ôø¹½Ñ¥™¥…Ñ¥½¸¹É•¥Á¥•¹Ñ%‘•¹Ñ¥Ñå%¤¥tì(€€€€€¥˜€¡É•¥Á¥•¹Ñ%‘Ì¹±•¹Ñ ¤ì(€€€€€€€½¹ÍÐÁ±…•¡½±‘•ÉÌ€ôÉ•¥Á¥•¹Ñ%‘Ì¹µ…À  ¤€ôø€ˆüˆ¤¹©½¥¸ ˆ°€ˆ¤ì(€€€€€€€½¹ÍÐm¥‘•¹Ñ¥Ñ¥•Ít€ô…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€€€M1P¥‘•¹Ñ¥Ñå}¥I=4¥‘•¹Ñ¥Ñ¥•Ì]!IÍÑ…ÑÕÌ€ô€…Ñ¥Ù”œ9¥‘•¹Ñ¥Ñå}¥%8€ ‘íÁ±…•¡½±‘•ÉÍô¤=HUAQ€°(€€€€€€€€€É•¥Á¥•¹Ñ%‘Ì°(€€€€€€€€¤ì(€€€€€€€½¹ÍÐ…Ñ¥Ù•%‘Ì€ô¹•ÜM•Ð¡¥‘•¹Ñ¥Ñ¥•Ì¹µ…À ¡¥‘•¹Ñ¥Ñä¤€ôø¥‘•¹Ñ¥Ñä¹¥‘•¹Ñ¥Ñå}¥¤¤ì(€€€€€€€¥˜€¡É•¥Á¥•¹Ñ%‘Ì¹Í½µ” ¡¥‘•¹Ñ¥Ñå%¤€ôø€……Ñ¥Ù•%‘Ì¹¡…Ì¡¥‘•¹Ñ¥Ñå%¤¤¤ì(€€€€€€€€€Ñ¡É½Ü=‰©•Ð¹…ÍÍ¥¸¡¹•ÜÉÉ½È ‰¹½Ñ¥™¥…Ñ¥½¸É•¥Á¥•¹Ð¥‘•¹Ñ¥Ñä¥ÌÕ¹…Ù…¥±…‰±”ˆ¤°ì½‘”è€‰É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}Õ¹…Ù…¥±…‰±”ˆô¤ì(€€€€€€€ô(€€€€€ô(€€€€€…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€%9MIP%9Q<¹½Ñ¥™¥…Ñ¥½¹}É•Í½±ÕÑ¥½¹Ì (€€€€€€€€€€Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°Í½ÕÉ•}•Ù•¹Ñ}¥°Á½±¥å}Ù•ÉÍ¥½¸°É•Í½±ÕÑ¥½¹}¡…Í °ÍÕÁÁÉ•ÍÍ•‘}©Í½¸°(€€€€€€€€€€¥¹Ñ•É¹…±}¹½Ñ¥™¥…Ñ¥½¹}½Õ¹Ð°‰±½­•‘}•áÑ•É¹…±}‘•±¥Ù•Éå}½Õ¹Ð°É•Í½±Ù•‘}…Ð(€€€€€€€€€¤Y1UL€ ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü¥€°(€€€€€€€m•Ù•¹Ð¹Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%°•Ù•¹Ð¹•Ù•¹Ñ%°Á½±¥åY•ÉÍ¥½¸°É•Í½±ÕÑ¥½¹!…Í °)M=8¹ÍÑÉ¥¹¥™ä¡ÍÕÁÁÉ•ÍÍ•¤°(€€€€€€€€¹½Ñ¥™¥…Ñ¥½¹Ì¹±•¹Ñ °•áÑ•É¹…±•±¥Ù•É¥•Ì¹±•¹Ñ °…Í5…É¥……Ñ”¡É•Í½±Ù•‘Ð¥t°(€€€€€€¤ì(€€€€€™½È€¡½¹ÍÐ¹½Ñ¥™¥…Ñ¥½¸½˜¹½Ñ¥™¥…Ñ¥½¹Ì¤ì(€€€€€€€…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€€€%9MIP%9Q<¹½Ñ¥™¥…Ñ¥½¹Ì (€€€€€€€€€€€€¹½Ñ¥™¥…Ñ¥½¹}¥°Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°Í½ÕÉ•}•Ù•¹Ñ}¥°É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥°(€€€€€€€€€€€€…Ñ•½Éä°¥µÁ½ÉÑ…¹”°Ñ¥Ñ±”°µ•ÍÍ…”°½¹Ñ•áÑ}…ÁÁ±¥…Ñ¥½¹}¥°½¹Ñ•áÑ}É•Í½ÕÉ•}ÑåÁ”°(€€€€€€€€€€€€½¹Ñ•áÑ}É•Í½ÕÉ•}¥°½ÕÉÉ•‘}…Ð°É•…Ñ•‘}…Ð°É•…‘}…Ð°…É¡¥Ù•‘}…Ð(€€€€€€€€€€€¤Y1UL€ ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°9U10°9U10¥€°(€€€€€€€€€m¹½Ñ¥™¥…Ñ¥½¸¹¹½Ñ¥™¥…Ñ¥½¹%°•Ù•¹Ð¹Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%°•Ù•¹Ð¹•Ù•¹Ñ%°(€€€€€€€€€€¹½Ñ¥™¥…Ñ¥½¸¹É•¥Á¥•¹Ñ%‘•¹Ñ¥Ñå%°¹½Ñ¥™¥…Ñ¥½¸¹…Ñ•½Éä°¹½Ñ¥™¥…Ñ¥½¸¹¥µÁ½ÉÑ…¹”°(€€€€€€€€€€¹½Ñ¥™¥…Ñ¥½¸¹Ñ¥Ñ±”°¹½Ñ¥™¥…Ñ¥½¸¹µ•ÍÍ…”°¹½Ñ¥™¥…Ñ¥½¸¹½¹Ñ•áÑÁÁ±¥…Ñ¥½¹%°(€€€€€€€€€€¹½Ñ¥™¥…Ñ¥½¸¹½¹Ñ•áÑI•Í½ÕÉ•QåÁ”°¹½Ñ¥™¥…Ñ¥½¸¹½¹Ñ•áÑI•Í½ÕÉ•%°(€€€€€€€€€€…Í5…É¥……Ñ”¡¹½Ñ¥™¥…Ñ¥½¸¹½ÕÉÉ•‘Ð¤°…Í5…É¥……Ñ”¡¹½Ñ¥™¥…Ñ¥½¸¹É•…Ñ•‘Ð¥t°(€€€€€€€€¤ì(€€€€€ô(€€€€€™½È€¡½¹ÍÐ‘•±¥Ù•Éä½˜•áÑ•É¹…±•±¥Ù•É¥•Ì¤ì(€€€€€€€…Ý…¥Ð½¹¹•Ñ¥½¸¹•á•ÕÑ” (€€€€€€€€€%9MIP%9Q<¹½Ñ¥™¥…Ñ¥½¹}•áÑ•É¹…±}‘•±¥Ù•É¥•Ì (€€€€€€€€€€€€‘•±¥Ù•Éå}¥°¹½Ñ¥™¥…Ñ¥½¹}¥°¡…¹¹•°°ÍÑ…ÑÕÌ°‰±½­•‘}É•…Í½¸°(€€€€€€€€€€€€ÁÉ½•ÍÍ¥¹}…ÑÑ•µÁÑÌ°…Ù…¥±…‰±•}…Ð°±…¥µ•‘}…Ð°±…¥µ•‘}‰ä°‘•±¥Ù•É•‘}…Ð°±…ÍÑ}•ÉÉ½É}½‘”°É•…Ñ•‘}…Ð(€€€€€€€€€€€¤Y1UL€ ü°€ü°€ü°€‰±½­•œ°€ü°€À°9U10°9U10°9U10°9U10°9U10°€ü¥€°(€€€€€€€€€m‘•±¥Ù•Éä¹‘•±¥Ù•Éå%°‘•±¥Ù•Éä¹¹½Ñ¥™¥…Ñ¥½¹%°‘•±¥Ù•Éä¹¡…¹¹•°°(€€€€€€€€€€‘•±¥Ù•Éä¹‰±½­•‘I•…Í½¸°…Í5…É¥……Ñ”¡‘•±¥Ù•Éä¹É•…Ñ•‘Ð¥t°(€€€€€€€€¤ì(€€€€€ô(€€€€€…Ý…¥ÐÑ¡¥Ì¸…ÁÁ•¹‘Õ‘¥Ð¡½¹¹•Ñ¥½¸°…Õ‘¥ÑÙ•¹Ð¤ì(€€€€€É•ÑÕÉ¸ìÉ•…Ñ•èÑÉÕ”°¹½Ñ¥™¥…Ñ¥½¹Ìè¹½Ñ¥™¥…Ñ¥½¹Ì¹±•¹Ñ °•áÑ•É¹…±•±¥Ù•É¥•Í	±½­•è•áÑ•É¹…±•±¥Ù•É¥•Ì¹±•¹Ñ ôì(€€€ô¤ì(€ô((€…Íå¹Œ±¥ÍÑ9½Ñ¥™¥…Ñ¥½¹Ì¡¥‘•¹Ñ¥Ñå%°±¥µ¥Ð€ô€ÄÀÀ¤ì(€€€½¹ÍÐÍ…™•1¥µ¥Ð€ô9Õµ‰•È¡±¥µ¥Ð¤ì(€€€¥˜€ …9Õµ‰•È¹¥Í%¹Ñ••È¡Í…™•1¥µ¥Ð¤ñðÍ…™•1¥µ¥Ð€ð€ÄñðÍ…™•1¥µ¥Ð€ø€ÈÀÀ¤Ñ¡É½Ü¹•ÜÉÉ½È ‰¥¹Ù…±¥¹½Ñ¥™¥…Ñ¥½¸±¥ÍÐ±¥µ¥Ðˆ¤ì(€€€½¹ÍÐmÉ½ÝÍt€ô…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€M1P¸¹¹½Ñ¥™¥…Ñ¥½¹}¥°¸¹Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°„¹‘¥ÍÁ±…å}¹…µ”LÍ½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¹…µ”°(€€€€€€€€¸¹…Ñ•½Éä°¸¹¥µÁ½ÉÑ…¹”°¸¹Ñ¥Ñ±”°¸¹µ•ÍÍ…”°¸¹½¹Ñ•áÑ}…ÁÁ±¥…Ñ¥½¹}¥°(€€€€€€€€¸¹½¹Ñ•áÑ}É•Í½ÕÉ•}ÑåÁ”°¸¹½¹Ñ•áÑ}É•Í½ÕÉ•}¥°¸¹½ÕÉÉ•‘}…Ð°¸¹É•…Ñ•‘}…Ð°(€€€€€€€€¸¹É•…‘}…Ð°¸¹…É¡¥Ù•‘}…Ð(€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹Ì¸(€€€€€€)=%8¥‘•¹Ñ¥Ñ¥•Ì¤=8¤¹¥‘•¹Ñ¥Ñå}¥€ô¸¹É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥9¤¹ÍÑ…ÑÕÌ€ô€…Ñ¥Ù”œ(€€€€€€)=%8…ÁÁ±¥…Ñ¥½¹Ì„=8„¹…ÁÁ±¥…Ñ¥½¹}¥€ô¸¹Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥(€€€€€€]!I¸¹É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥€ô€ü9¸¹…É¡¥Ù•‘}…Ð%L9U10(€€€€€€=IH	d¸¹½ÕÉÉ•‘}…ÐM°¸¹¹½Ñ¥™¥…Ñ¥½¹}¥M1%5%P€‘íÍ…™•1¥µ¥Ñõ€°(€€€€€m¥‘•¹Ñ¥Ñå%‘t°(€€€€¤ì(€€€É•ÑÕÉ¸É½ÝÌ¹µ…À ¡É½Ü¤€ôø€¡ì(€€€€€¹½Ñ¥™¥…Ñ¥½¹%èÉ½Ü¹¹½Ñ¥™¥…Ñ¥½¹}¥°Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%èÉ½Ü¹Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°(€€€€€Í½ÕÉ•ÁÁ±¥…Ñ¥½¹9…µ”èÉ½Ü¹Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¹…µ”°…Ñ•½ÉäèÉ½Ü¹…Ñ•½Éä°(€€€€€¥µÁ½ÉÑ…¹”èÉ½Ü¹¥µÁ½ÉÑ…¹”°Ñ¥Ñ±”èÉ½Ü¹Ñ¥Ñ±”°µ•ÍÍ…”èÉ½Ü¹µ•ÍÍ…”°(€€€€€½¹Ñ•áÑÁÁ±¥…Ñ¥½¹%èÉ½Ü¹½¹Ñ•áÑ}…ÁÁ±¥…Ñ¥½¹}¥°½¹Ñ•áÑI•Í½ÕÉ•QåÁ”èÉ½Ü¹½¹Ñ•áÑ}É•Í½ÕÉ•}ÑåÁ”°(€€€€€½¹Ñ•áÑI•Í½ÕÉ•%èÉ½Ü¹½¹Ñ•áÑ}É•Í½ÕÉ•}¥°½ÕÉÉ•‘Ðè…Í%Í¼¡É½Ü¹½ÕÉÉ•‘}…Ð¤°(€€€€€É•…Ñ•‘Ðè…Í%Í¼¡É½Ü¹É•…Ñ•‘}…Ð¤°É•…‘Ðè…Í%Í¼¡É½Ü¹É•…‘}…Ð¤°…É¡¥Ù•‘Ðè…Í%Í¼¡É½Ü¹…É¡¥Ù•‘}…Ð¤°(€€€ô¤¤ì(€ô((€…Íå¹Œ½Õ¹ÑU¹É•…‘9½Ñ¥™¥…Ñ¥½¹Ì¡¥‘•¹Ñ¥Ñå%¤ì(€€€½¹ÍÐmÉ½ÝÍt€ô…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€M1P=U9P ¨¤L½Õ¹ÐI=4¹½Ñ¥™¥…Ñ¥½¹Ì¸(€€€€€€)=%8¥‘•¹Ñ¥Ñ¥•Ì¤=8¤¹¥‘•¹Ñ¥Ñå}¥€ô¸¹É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥9¤¹ÍÑ…ÑÕÌ€ô€…Ñ¥Ù”œ(€€€€€€]!I¸¹É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥€ô€ü9¸¹É•…‘}…Ð%L9U109¸¹…É¡¥Ù•‘}…Ð%L9U11€°(€€€€€m¥‘•¹Ñ¥Ñå%‘t°(€€€€¤ì(€€€É•ÑÕÉ¸9Õµ‰•È¡É½ÝÍlÁtü¹½Õ¹Ð€üü€À¤ì(€ô((€…Íå¹ŒÉ•½É‘9½Ñ¥™¥…Ñ¥½¹AÉ½•ÍÍ¥¹IÕ¸¡ì(€€€ÍÑ…ÑÕÌ°ÍÑ…ÉÑ•‘Ð°™¥¹¥Í¡•‘Ð°•ÉÉ½É½‘”°±…¥µ•°ÁÉ½•ÍÍ•°É•ÑÉ¥•°ÅÕ…É…¹Ñ¥¹•°(€ô¤ì(€€€½¹ÍÐÙ…±¥‘ÉÉ½É½‘”€ôÑåÁ•½˜•ÉÉ½É½‘”€ôôô€‰ÍÑÉ¥¹œˆ€˜˜€½ym„µéum„µèÀ´å|èµuìÀ°Üåô¼¹Ñ•ÍÐ¡•ÉÉ½É½‘”¤ì(€€€¥˜€ …l‰ÍÕ••‘•ˆ°€‰™…¥±•‰t¹¥¹±Õ‘•Ì¡ÍÑ…ÑÕÌ¤ñð€„¡ÍÑ…ÉÑ•‘Ð¥¹ÍÑ…¹•½˜…Ñ”¤ñð(€€€€€€€€„¡™¥¹¥Í¡•‘Ð¥¹ÍÑ…¹•½˜…Ñ”¤ñð™¥¹¥Í¡•‘Ð€ðÍÑ…ÉÑ•‘Ðñð(€€€€€€€€¡ÍÑ…ÑÕÌ€ôôô€‰™…¥±•ˆ¤€„ôôÙ…±¥‘ÉÉ½É½‘”ñð€¡ÍÑ…ÑÕÌ€ôôô€‰ÍÕ••‘•ˆ€˜˜•ÉÉ½É½‘”€„ôô¹Õ±°¤¤ì(€€€€€Ñ¡É½Ü¹•ÜÉÉ½È ‰¥¹Ù…±¥¹½Ñ¥™¥…Ñ¥½¸ÁÉ½•ÍÍ¥¹œ½ÕÑ½µ”ˆ¤ì(€€€ô(€€€½¹ÍÐ½Õ¹ÑÌ€ôm±…¥µ•°ÁÉ½•ÍÍ•°É•ÑÉ¥•°ÅÕ…É…¹Ñ¥¹•‘t¹µ…À¡9Õµ‰•È¤ì(€€€¥˜€¡½Õ¹ÑÌ¹Í½µ” ¡Ù…±Õ”¤€ôø€…9Õµ‰•È¹¥Í%¹Ñ••È¡Ù…±Õ”¤ñðÙ…±Õ”€ð€ÀñðÙ…±Õ”€ø€ÄÀÀ¤¤ì(€€€€€Ñ¡É½Ü¹•ÜÉÉ½È ‰¥¹Ù…±¥¹½Ñ¥™¥…Ñ¥½¸ÁÉ½•ÍÍ¥¹œ½Õ¹ÑÌˆ¤ì(€€€ô(€€€…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€%9MIP%9Q<¹½Ñ¥™¥…Ñ¥½¹}ÁÉ½•ÍÍ¥¹}ÍÑ…Ñ” (€€€€€€€€½¹ÍÕµ•É}¥°±…ÍÑ}ÍÑ…ÉÑ•‘}…Ð°±…ÍÑ}™¥¹¥Í¡•‘}…Ð°±…ÍÑ}ÍÑ…ÑÕÌ°±…ÍÑ}•ÉÉ½É}½‘”°(€€€€€€€€±…ÍÑ}±…¥µ•°±…ÍÑ}ÁÉ½•ÍÍ•°±…ÍÑ}É•ÑÉ¥•°±…ÍÑ}ÅÕ…É…¹Ñ¥¹•°Ù•ÉÍ¥½¸(€€€€€€€¤Y1UL€ ¥¹Ñ•É¹…°µµ…Ñ•É¥…±¥é•ÈµØÄœ°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€ü°€Ä¤(€€€€€€=8UA1%Q-dUAQ(€€€€€€€€±…ÍÑ}ÍÑ…ÉÑ•‘}…Ð€ôY1UL¡±…ÍÑ}ÍÑ…ÉÑ•‘}…Ð¤°±…ÍÑ}™¥¹¥Í¡•‘}…Ð€ôY1UL¡±…ÍÑ}™¥¹¥Í¡•‘}…Ð¤°(€€€€€€€€±…ÍÑ}ÍÑ…ÑÕÌ€ôY1UL¡±…ÍÑ}ÍÑ…ÑÕÌ¤°±…ÍÑ}•ÉÉ½É}½‘”€ôY1UL¡±…ÍÑ}•ÉÉ½É}½‘”¤°(€€€€€€€€±…ÍÑ}±…¥µ•€ôY1UL¡±…ÍÑ}±…¥µ•¤°±…ÍÑ}ÁÉ½•ÍÍ•€ôY1UL¡±…ÍÑ}ÁÉ½•ÍÍ•¤°(€€€€€€€€±…ÍÑ}É•ÑÉ¥•€ôY1UL¡±…ÍÑ}É•ÑÉ¥•¤°±…ÍÑ}ÅÕ…É…¹Ñ¥¹•€ôY1UL¡±…ÍÑ}ÅÕ…É…¹Ñ¥¹•¤°(€€€€€€€€Ù•ÉÍ¥½¸€ôÙ•ÉÍ¥½¸€¬€Å€°(€€€€€m…Í5…É¥……Ñ”¡ÍÑ…ÉÑ•‘Ð¤°…Í5…É¥……Ñ”¡™¥¹¥Í¡•‘Ð¤°ÍÑ…ÑÕÌ°•ÉÉ½É½‘”°(€€€€€€½Õ¹ÑÍlÁt°½Õ¹ÑÍlÅt°½Õ¹ÑÍlÉt°½Õ¹ÑÍlÍut°(€€€€¤ì(€ô((€…Íå¹Œ•Ñ9½Ñ¥™¥…Ñ¥½¹=Á•É…Ñ¥½¹ÍM¹…ÁÍ¡½Ð¡±¥µ¥Ð€ô€ÔÀ¤ì(€€€½¹ÍÐÍ…™•1¥µ¥Ð€ô9Õµ‰•È¡±¥µ¥Ð¤ì(€€€¥˜€ …9Õµ‰•È¹¥Í%¹Ñ••È¡Í…™•1¥µ¥Ð¤ñðÍ…™•1¥µ¥Ð€ð€ÄñðÍ…™•1¥µ¥Ð€ø€ÄÀÀ¤ì(€€€€€Ñ¡É½Ü¹•ÜÉÉ½È ‰¥¹Ù…±¥¹½Ñ¥™¥…Ñ¥½¸½Á•É…Ñ¥½¹Ì±¥µ¥Ðˆ¤ì(€€€ô(€€€½¹ÍÐm•Ù•¹ÑI½ÝÌ°¹½Ñ¥™¥…Ñ¥½¹I½ÝÌ°‘•±¥Ù•ÉåI½ÝÌ°ÍÕÁÁÉ•ÍÍ¥½¹I½ÝÌ°É••¹ÑI½ÝÌ°ÁÉ½•ÍÍ½ÉI½ÝÍt€ô…Ý…¥ÐAÉ½µ¥Í”¹…±°¡l(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1P=U9P ¨¤LÑ½Ñ…°°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€Á•¹‘¥¹œœ¤°€À¤LÁ•¹‘¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€ÁÉ½•ÍÍ¥¹œœ¤°€À¤LÁÉ½•ÍÍ¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€É•ÑÉäœ¤°€À¤LÉ•ÑÉå¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€ÁÉ½•ÍÍ•œ¤°€À¤LÁÉ½•ÍÍ•°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€ÅÕ…É…¹Ñ¥¹•œ¤°€À¤LÅÕ…É…¹Ñ¥¹•°(€€€€€€€€€€5%8¡M]!8ÍÑ…ÑÕÌ%8€ Á•¹‘¥¹œœ°€É•ÑÉäœ¤Q!8…Ù…¥±…‰±•}…Ð9¤L½±‘•ÍÑ}…Ù…¥±…‰±•}…Ð°(€€€€€€€€€€5`¡É••¥Ù•‘}…Ð¤L±…ÍÑ}É••¥Ù•‘}…Ð°(€€€€€€€€€€5`¡ÁÉ½•ÍÍ•‘}…Ð¤L±…ÍÑ}ÁÉ½•ÍÍ•‘}…Ð(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}•Ù•¹ÑÍ€°(€€€€€€¤°(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1P=U9P ¨¤LÑ½Ñ…°°(€€€€€€€€€€=1M¡MU4¡É•…‘}…Ð%L9U109…É¡¥Ù•‘}…Ð%L9U10¤°€À¤LÕ¹É•…°(€€€€€€€€€€=1M¡MU4¡…É¡¥Ù•‘}…Ð%L9=P9U10¤°€À¤L…É¡¥Ù•(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹Í€°(€€€€€€¤°(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1P=U9P ¨¤LÑ½Ñ…°°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€‰±½­•œ¤°€À¤L‰±½­•°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ðø€‰±½­•œ¤°€À¤L¹½¹}‰±½­•°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€Á•¹‘¥¹œœ¤°€À¤LÁ•¹‘¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€ÁÉ½•ÍÍ¥¹œœ¤°€À¤LÁÉ½•ÍÍ¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€É•ÑÉäœ¤°€À¤LÉ•ÑÉå¥¹œ°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€‘•±¥Ù•É•œ¤°€À¤L‘•±¥Ù•É•°(€€€€€€€€€€=1M¡MU4¡ÍÑ…ÑÕÌ€ô€ÅÕ…É…¹Ñ¥¹•œ¤°€À¤LÅÕ…É…¹Ñ¥¹•(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}•áÑ•É¹…±}‘•±¥Ù•É¥•Í€°(€€€€€€¤°(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1P(€€€€€€€€€€=1M¡MU4¡MP¡)M=9}U9EU=Q¡)M=9}aQIP¡ÍÕÁÁÉ•ÍÍ•‘}©Í½¸°€œ¹½Ý¹}…Ñ¥½¸œ¤¤LU9M%9¤¤°€À¤L½Ý¹}…Ñ¥½¸°(€€€€€€€€€€=1M¡MU4¡MP¡)M=9}U9EU=Q¡)M=9}aQIP¡ÍÕÁÁÉ•ÍÍ•‘}©Í½¸°€œ¹ÁÉ•™•É•¹•Ìœ¤¤LU9M%9¤¤°€À¤LÁÉ•™•É•¹•Ì°(€€€€€€€€€€=1M¡MU4¡MP¡)M=9}U9EU=Q¡)M=9}aQIP¡ÍÕÁÁÉ•ÍÍ•‘}©Í½¸°€œ¹Õ¹±¥¹­•‘}¥‘•¹Ñ¥Ñäœ¤¤LU9M%9¤¤°€À¤LÕ¹±¥¹­•‘}¥‘•¹Ñ¥Ñä(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}É•Í½±ÕÑ¥½¹Í€°(€€€€€€¤°(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1PÍ½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°Í½ÕÉ•}•Ù•¹Ñ}¥°Á½±¥å}Ù•ÉÍ¥½¸°ÍÕÁÁÉ•ÍÍ•‘}©Í½¸°(€€€€€€€€€€¥¹Ñ•É¹…±}¹½Ñ¥™¥…Ñ¥½¹}½Õ¹Ð°‰±½­•‘}•áÑ•É¹…±}‘•±¥Ù•Éå}½Õ¹Ð°É•Í½±Ù•‘}…Ð(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}É•Í½±ÕÑ¥½¹Ì(€€€€€€€€=IH	dÉ•Í½±Ù•‘}…ÐM°Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°Í½ÕÉ•}•Ù•¹Ñ}¥(€€€€€€€€1%5%P€‘íÍ…™•1¥µ¥Ñõ€°(€€€€€€¤°(€€€€€Ñ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€€M1P±…ÍÑ}ÍÑ…ÉÑ•‘}…Ð°±…ÍÑ}™¥¹¥Í¡•‘}…Ð°±…ÍÑ}ÍÑ…ÑÕÌ°±…ÍÑ}•ÉÉ½É}½‘”°(€€€€€€€€€€±…ÍÑ}±…¥µ•°±…ÍÑ}ÁÉ½•ÍÍ•°±…ÍÑ}É•ÑÉ¥•°±…ÍÑ}ÅÕ…É…¹Ñ¥¹•°Ù•ÉÍ¥½¸(€€€€€€€€I=4¹½Ñ¥™¥…Ñ¥½¹}ÁÉ½•ÍÍ¥¹}ÍÑ…Ñ”(€€€€€€€€]!I½¹ÍÕµ•É}¥€ô€¥¹Ñ•É¹…°µµ…Ñ•É¥…±¥é•ÈµØÄ€°(€€€€€€¤°(€€€t¤ì(€€€½¹ÍÐ•Ù•¹ÑÌ€ô•Ù•¹ÑI½ÝÍlÁulÁt€üüíôì(€€€½¹ÍÐ¹½Ñ¥™¥…Ñ¥½¹Ì€ô¹½Ñ¥™¥…Ñ¥½¹I½ÝÍlÁulÁt€üüíôì(€€€½¹ÍÐ‘•±¥Ù•É¥•Ì€ô‘•±¥Ù•ÉåI½ÝÍlÁulÁt€üüíôì(€€€½¹ÍÐÍÕÁÁÉ•ÍÍ¥½¹Ì€ôÍÕÁÁÉ•ÍÍ¥½¹I½ÝÍlÁulÁt€üüíôì(€€€½¹ÍÐÁÉ½•ÍÍ½È€ôÁÉ½•ÍÍ½ÉI½ÝÍlÁulÁt€üü¹Õ±°ì(€€€½¹ÍÐ¹Õµ‰•È€ô€¡Ù…±Õ”¤€ôø9Õµ‰•È¡Ù…±Õ”€üü€À¤ì(€€€É•ÑÕÉ¸ì(€€€€€•Ù•¹ÑÌèì(€€€€€€€Ñ½Ñ…°è¹Õµ‰•È¡•Ù•¹ÑÌ¹Ñ½Ñ…°¤°Á•¹‘¥¹œè¹Õµ‰•È¡•Ù•¹ÑÌ¹Á•¹‘¥¹œ¤°ÁÉ½•ÍÍ¥¹œè¹Õµ‰•È¡•Ù•¹ÑÌ¹ÁÉ½•ÍÍ¥¹œ¤°(€€€€€€€É•ÑÉå¥¹œè¹Õµ‰•È¡•Ù•¹ÑÌ¹É•ÑÉå¥¹œ¤°ÁÉ½•ÍÍ•è¹Õµ‰•È¡•Ù•¹ÑÌ¹ÁÉ½•ÍÍ•¤°ÅÕ…É…¹Ñ¥¹•è¹Õµ‰•È¡•Ù•¹ÑÌ¹ÅÕ…É…¹Ñ¥¹•¤°(€€€€€€€½±‘•ÍÑÙ…¥±…‰±•Ðè…Í%Í¼¡•Ù•¹ÑÌ¹½±‘•ÍÑ}…Ù…¥±…‰±•}…Ð¤°±…ÍÑI••¥Ù•‘Ðè…Í%Í¼¡•Ù•¹ÑÌ¹±…ÍÑ}É••¥Ù•‘}…Ð¤°(€€€€€€€±…ÍÑAÉ½•ÍÍ•‘Ðè…Í%Í¼¡•Ù•¹ÑÌ¹±…ÍÑ}ÁÉ½•ÍÍ•‘}…Ð¤°(€€€€€ô°(€€€€€¹½Ñ¥™¥…Ñ¥½¹Ìèì(€€€€€€€Ñ½Ñ…°è¹Õµ‰•È¡¹½Ñ¥™¥…Ñ¥½¹Ì¹Ñ½Ñ…°¤°Õ¹É•…è¹Õµ‰•È¡¹½Ñ¥™¥…Ñ¥½¹Ì¹Õ¹É•…¤°…É¡¥Ù•è¹Õµ‰•È¡¹½Ñ¥™¥…Ñ¥½¹Ì¹…É¡¥Ù•¤°(€€€€€ô°(€€€€€•áÑ•É¹…±•±¥Ù•É¥•Ìèì(€€€€€€€Ñ½Ñ…°è¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹Ñ½Ñ…°¤°‰±½­•è¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹‰±½­•¤°¹½¹	±½­•è¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹¹½¹}‰±½­•¤°(€€€€€€€Á•¹‘¥¹œè¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹Á•¹‘¥¹œ¤°ÁÉ½•ÍÍ¥¹œè¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹ÁÉ½•ÍÍ¥¹œ¤°É•ÑÉå¥¹œè¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹É•ÑÉå¥¹œ¤°(€€€€€€€‘•±¥Ù•É•è¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹‘•±¥Ù•É•¤°ÅÕ…É…¹Ñ¥¹•è¹Õµ‰•È¡‘•±¥Ù•É¥•Ì¹ÅÕ…É…¹Ñ¥¹•¤°(€€€€€ô°(€€€€€ÍÕÁÁÉ•ÍÍ¥½¹Ìèì(€€€€€€€½Ý¹Ñ¥½¸è¹Õµ‰•È¡ÍÕÁÁÉ•ÍÍ¥½¹Ì¹½Ý¹}…Ñ¥½¸¤°ÁÉ•™•É•¹•Ìè¹Õµ‰•È¡ÍÕÁÁÉ•ÍÍ¥½¹Ì¹ÁÉ•™•É•¹•Ì¤°(€€€€€€€Õ¹±¥¹­•‘%‘•¹Ñ¥Ñäè¹Õµ‰•È¡ÍÕÁÁÉ•ÍÍ¥½¹Ì¹Õ¹±¥¹­•‘}¥‘•¹Ñ¥Ñä¤°(€€€€€ô°(€€€€€ÁÉ½•ÍÍ½ÈèÁÉ½•ÍÍ½È€üì(€€€€€€€ÍÑ…ÑÕÌèÁÉ½•ÍÍ½È¹±…ÍÑ}ÍÑ…ÑÕÌ°±…ÍÑMÑ…ÉÑ•‘Ðè…Í%Í¼¡ÁÉ½•ÍÍ½È¹±…ÍÑ}ÍÑ…ÉÑ•‘}…Ð¤°(€€€€€€€±…ÍÑ¥¹¥Í¡•‘Ðè…Í%Í¼¡ÁÉ½•ÍÍ½È¹±…ÍÑ}™¥¹¥Í¡•‘}…Ð¤°•ÉÉ½É½‘”èÁÉ½•ÍÍ½È¹±…ÍÑ}•ÉÉ½É}½‘”°(€€€€€€€±…¥µ•è¹Õµ‰•È¡ÁÉ½•ÍÍ½È¹±…ÍÑ}±…¥µ•¤°ÁÉ½•ÍÍ•è¹Õµ‰•È¡ÁÉ½•ÍÍ½È¹±…ÍÑ}ÁÉ½•ÍÍ•¤°(€€€€€€€É•ÑÉ¥•è¹Õµ‰•È¡ÁÉ½•ÍÍ½È¹±…ÍÑ}É•ÑÉ¥•¤°ÅÕ…É…¹Ñ¥¹•è¹Õµ‰•È¡ÁÉ½•ÍÍ½È¹±…ÍÑ}ÅÕ…É…¹Ñ¥¹•¤°(€€€€€€€Ù•ÉÍ¥½¸è¹Õµ‰•È¡ÁÉ½•ÍÍ½È¹Ù•ÉÍ¥½¸¤°(€€€€€ô€èìÍÑ…ÑÕÌè€‰¹•Ù•É}ÉÕ¸ˆ°±…ÍÑMÑ…ÉÑ•‘Ðè¹Õ±°°±…ÍÑ¥¹¥Í¡•‘Ðè¹Õ±°°•ÉÉ½É½‘”è¹Õ±°°(€€€€€€€±…¥µ•è€À°ÁÉ½•ÍÍ•è€À°É•ÑÉ¥•è€À°ÅÕ…É…¹Ñ¥¹•è€À°Ù•ÉÍ¥½¸è€Àô°(€€€€€É••¹ÑI•Í½±ÕÑ¥½¹ÌèÉ••¹ÑI½ÝÍlÁt¹µ…À ¡É½Ü¤€ôø€¡ì(€€€€€€€Í½ÕÉ•ÁÁ±¥…Ñ¥½¹%èÉ½Ü¹Í½ÕÉ•}…ÁÁ±¥…Ñ¥½¹}¥°•Ù•¹Ñ%èÉ½Ü¹Í½ÕÉ•}•Ù•¹Ñ}¥°(€€€€€€€Á½±¥åY•ÉÍ¥½¸èÉ½Ü¹Á½±¥å}Ù•ÉÍ¥½¸°ÍÕÁÁÉ•ÍÍ•èÁ…ÉÍ•)Í½¸¡É½Ü¹ÍÕÁÁÉ•ÍÍ•‘}©Í½¸¤°(€€€€€€€¥¹Ñ•É¹…±9½Ñ¥™¥…Ñ¥½¹½Õ¹Ðè¹Õµ‰•È¡É½Ü¹¥¹Ñ•É¹…±}¹½Ñ¥™¥…Ñ¥½¹}½Õ¹Ð¤°(€€€€€€€‰±½­•‘áÑ•É¹…±•±¥Ù•Éå½Õ¹Ðè¹Õµ‰•È¡É½Ü¹‰±½­•‘}•áÑ•É¹…±}‘•±¥Ù•Éå}½Õ¹Ð¤°(€€€€€€€É•Í½±Ù•‘Ðè…Í%Í¼¡É½Ü¹É•Í½±Ù•‘}…Ð¤°(€€€€€ô¤¤°(€€€ôì(€ô((€…Íå¹Œµ…É­9½Ñ¥™¥…Ñ¥½¹I•…¡ì¥‘•¹Ñ¥Ñå%°¹½Ñ¥™¥…Ñ¥½¹%°É•…‘Ðô¤ì(€€€½¹ÍÐmÉ•ÍÕ±Ñt€ô…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€UAQ¹½Ñ¥™¥…Ñ¥½¹ÌMPÉ•…‘}…Ð€ô€ü(€€€€€€]!I¹½Ñ¥™¥…Ñ¥½¹}¥€ô€ü9É•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥€ô€ü9É•…‘}…Ð%L9U109…É¡¥Ù•‘}…Ð%L9U10(€€€€€€€€9a%MQL€¡M1P€ÄI=4¥‘•¹Ñ¥Ñ¥•Ì¤]!I¤¹¥‘•¹Ñ¥Ñå}¥€ô€ü9¤¹ÍÑ…ÑÕÌ€ô€…Ñ¥Ù”œ¥€°(€€€€€m…Í5…É¥……Ñ”¡É•…‘Ð¤°¹½Ñ¥™¥…Ñ¥½¹%°¥‘•¹Ñ¥Ñå%°¥‘•¹Ñ¥Ñå%‘t°(€€€€¤ì(€€€É•ÑÕÉ¸ì¡…¹•èÉ•ÍÕ±Ð¹…™™•Ñ•‘I½ÝÌ€ôôô€Äôì(€ô((€…Íå¹Œµ…É­±±9½Ñ¥™¥…Ñ¥½¹ÍI•…¡ì¥‘•¹Ñ¥Ñå%°É•…‘Ðô¤ì(€€€½¹ÍÐmÉ•ÍÕ±Ñt€ô…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€UAQ¹½Ñ¥™¥…Ñ¥½¹ÌMPÉ•…‘}…Ð€ô€ü(€€€€€€]!IÉ•¥Á¥•¹Ñ}¥‘•¹Ñ¥Ñå}¥€ô€ü9É•…‘}…Ð%L9U109…É¡¥Ù•‘}…Ð%L9U10(€€€€€€€€9a%MQL€¡M1P€ÄI=4¥‘•¹Ñ¥Ñ¥•Ì¤]!I¤¹¥‘•¹Ñ¥Ñå}¥€ô€ü9¤¹ÍÑ…ÑÕÌ€ô€…Ñ¥Ù”œ¥€°(€€€€€m…Í5…É¥……Ñ”¡É•…‘Ð¤°¥‘•¹Ñ¥Ñå%°¥‘•¹Ñ¥Ñå%‘t°(€€€€¤ì(€€€É•ÑÕÉ¸ì¡…¹•è9Õµ‰•È¡É•ÍÕ±Ð¹…™™•Ñ•‘I½ÝÌ¤ôì(€ô((€…Íå¹ŒÙ•É¥™åÕ‘¥Ñ¡…¥¸ ¤ì(€€€½¹ÍÐmÉ½ÝÍt€ô…Ý…¥ÐÑ¡¥Ì¹Á½½°¹•á•ÕÑ” (€€€€€€‰M1P•Ù•¹Ñ}Á…å±½…‘}©Í½¸°ÁÉ•Ù¥½ÕÍ}¡…Í °•Ù•¹Ñ}¡…Í I=4…Õ‘¥Ñ}•Ù•¹ÑÌ=IH	dÍ•ÅÕ•¹”ˆ°(€€€€¤ì(€€€É•ÑÕÉ¸Ù•É¥™åÕ‘¥Ñ¡…¥¸¡É½ÝÌ¹µ…À ¡É½Ü¤€ôø€¡ì(€€€€€•Ù•¹ÐèÁ…ÉÍ•)Í½¸¡É½Ü¹•Ù•¹Ñ}Á…å±½…‘}©Í½¸¤°ÁÉ•Ù¥½ÕÍ!…Í èÉ½Ü¹ÁÉ•Ù¥½ÕÍ}¡…Í °•Ù•¹Ñ!…Í èÉ½Ü¹•Ù•¹Ñ}¡…Í °(€€€ô¤¤¤ì(€ô)ô(