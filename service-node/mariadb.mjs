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
        "SELECT * FROM external_identity_link_requests WHERE request_id = ? FOR UPDATE", [requestId],
      );
      const request = requests[0];
      if (!request) throw new Error("link request not found");
      if (request.status !== "pending") throw new Error("link request is not pending");
      if (now >= new Date(request.expires_at)) throw new Error("link request has expired");
      const [identities] = await connection.execute(
        "SELECT status FROM identities WHERE identity_id = ? FOR UPDATE", [identityId],
      );
      if (!identities.length) throw new Error("NSK identity not found");
      if (identities[0].status !== "active") throw new Error("NSK identity is not active");
      const link = {
        externalIdentityId: randomUUID(), identityId, issuer: request.issuer,
        subject: request.subject, providerKey: request.provider_key, status: "active",
        linkedAt: now.toISOString(),
      };
      await connection.execute(
        `INSERT INTO external_identities(
           external_identity_id, identity_id, issuer, subject, provider_key, principal_hash, status, linked_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
        [link.externalIdentityId, identityId, link.issuer, link.subject, link.providerKey,
         externalPrincipalKey(link.issuer, link.subject), asMariaDate(link.linkedAt)],
      );
      await connection.execute(
        `UPDATE external_identity_link_requests SET status = 'approved', target_identity_id = ?,
           decided_by = ?, decision_justification = ? WHERE request_id = ?`,
        [identityId, decidedBy, justification.trim(), requestId],
      );
      await this.#appendAudit(connection, auditEvent);
      return link;
    });
  }

  async rejectLinkRequest(requestId, decidedBy, justification, auditEvent) {
    if (!String(justification ?? "").trim()) throw new Error("rejection justification is required");
    if (auditEvent.action !== "external_identity.link_rejected") throw new Error("invalid audit action for link rejection");
    if (auditEvent.actor_id !== decidedBy) throw new Error("audit actor must match decision maker");
    return this.#transaction(async (connection) => {
      const [requests] = await connection.execute(
        "SELECT * FROM external_identity_link_requests WHERE request_id = ? FOR UPDATE", [requestId],
      );
      const request = requests[0];
      if (!request) throw new Error("link request not found");
      if (request.status !== "pending") throw new Error("link request is not pending");
      await connection.execute(
        `UPDATE external_identity_link_requests SET status = 'rejected', decided_by = ?,
           decision_justification = ? WHERE request_id = ?`,
        [decidedBy, justification.trim(), requestId],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async saveAssignment(assignment, auditEvent) {
    if (auditEvent.subject_id !== assignment.subjectId || auditEvent.application_id !== assignment.applicationId) {
      throw new Error("audit context must match assignment");
    }
    return this.#transaction(async (connection) => {
      const [existing] = await connection.execute(
        "SELECT version FROM access_assignments WHERE assignment_id = ? FOR UPDATE", [assignment.assignmentId],
      );
      const previousVersion = existing[0]?.version;
      if (previousVersion === undefined && assignment.version !== 1) throw new Error("new assignment version must be 1");
      if (previousVersion !== undefined && assignment.version !== previousVersion + 1) throw new Error("stale assignment version");
      if (previousVersion !== undefined && !auditEvent.previous_value) throw new Error("previous value is required for update");
      await connection.execute(
        `INSERT INTO access_assignments(
           assignment_id, subject_id, application_id, role_id, permissions_json,
           scope_type, scope_id, conditions_json, status, valid_from, valid_until,
           reason, decided_by, inherited_from_group, version
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), permissions_json = VALUES(permissions_json),
           scope_type = VALUES(scope_type), scope_id = VALUES(scope_id), conditions_json = VALUES(conditions_json),
           status = VALUES(status), valid_from = VALUES(valid_from), valid_until = VALUES(valid_until),
           reason = VALUES(reason), decided_by = VALUES(decided_by),
           inherited_from_group = VALUES(inherited_from_group), version = VALUES(version)`,
        [assignment.assignmentId, assignment.subjectId, assignment.applicationId, assignment.roleId,
         JSON.stringify([...assignment.permissions].sort()), assignment.scopeType, assignment.scopeId,
         JSON.stringify([...assignment.conditions].sort()), assignment.status, asMariaDate(assignment.validFrom),
         asMariaDate(assignment.validUntil), assignment.reason ?? "", assignment.decidedBy ?? null,
         assignment.inheritedFromGroup ?? null, assignment.version],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async getIdentity(identityId) {
    const [rows] = await this.pool.execute(
      "SELECT identity_id, email, display_name, status FROM identities WHERE identity_id = ?", [identityId],
    );
    const row = rows[0];
    return row ? { identityId: row.identity_id, email: row.email, displayName: row.display_name, status: row.status } : null;
  }

  async listIdentities(status = null) {
    const [rows] = status
      ? await this.pool.execute(
        "SELECT identity_id, email, display_name, status FROM identities WHERE status = ? ORDER BY display_name, identity_id", [status],
      )
      : await this.pool.execute(
        "SELECT identity_id, email, display_name, status FROM identities ORDER BY display_name, identity_id",
      );
    return rows.map((row) => ({
      identityId: row.identity_id, email: row.email,
      displayName: row.display_name, status: row.status,
    }));
  }

  async getApplication(applicationId) {
    const [rows] = await this.pool.execute(
      "SELECT application_id, display_name, status, registration_policy FROM applications WHERE application_id = ?",
      [applicationId],
    );
    const row = rows[0];
    return row ? { applicationId: row.application_id, displayName: row.display_name, status: row.status, registrationPolicy: row.registration_policy } : null;
  }

  async listApplications() {
    const [rows] = await this.pool.execute(
      "SELECT application_id, display_name, status, registration_policy FROM applications ORDER BY display_name, application_id",
    );
    return rows.map((row) => ({
      applicationId: row.application_id, displayName: row.display_name,
      status: row.status, registrationPolicy: row.registration_policy,
    }));
  }

  async getLatestApplicationAccessCatalog(applicationId) {
    const [rows] = await this.pool.execute(
      `SELECT * FROM application_access_catalog_versions
       WHERE application_id = ? ORDER BY catalog_version DESC LIMIT 1`, [applicationId],
    );
    return mapApplicationAccessCatalog(rows[0]);
  }

  async listLatestApplicationAccessCatalogs() {
    const [rows] = await this.pool.execute(
      `SELECT catalog.* FROM application_access_catalog_versions catalog
       INNER JOIN (
         SELECT application_id, MAX(catalog_version) AS catalog_version
         FROM application_access_catalog_versions GROUP BY application_id
       ) latest ON latest.application_id = catalog.application_id
         AND latest.catalog_version = catalog.catalog_version
       ORDER BY catalog.application_id`,
    );
    return rows.map(mapApplicationAccessCatalog);
  }

  async saveApplicationRedirectUri(applicationId, redirectUri, auditEvent) {
    const redirectHash = createHash("sha256").update(redirectUri, "utf8").digest("hex");
    return this.#transaction(async (connection) => {
      await connection.execute(
        `INSERT INTO application_redirect_uris(application_id, redirect_uri, redirect_uri_hash, status)
         VALUES (?, ?, ?, 'active')
         ON DUPLICATE KEY UPDATE redirect_uri = VALUES(redirect_uri), status = 'active'`,
        [applicationId, redirectUri, redirectHash],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async isApplicationRedirectUriAllowed(applicationId, redirectUri) {
    const redirectHash = createHash("sha256").update(redirectUri, "utf8").digest("hex");
    const [rows] = await this.pool.execute(
      `SELECT 1 FROM application_redirect_uris
       WHERE application_id = ? AND redirect_uri_hash = ? AND redirect_uri = ? AND status = 'active'`,
      [applicationId, redirectHash, redirectUri],
    );
    return rows.length === 1;
  }

  async getApplicationRedirectUri(applicationId, redirectUri) {
    const redirectHash = createHash("sha256").update(redirectUri, "utf8").digest("hex");
    const [rows] = await this.pool.execute(
      `SELECT application_id, redirect_uri, status FROM application_redirect_uris
       WHERE application_id = ? AND redirect_uri_hash = ? AND redirect_uri = ?`,
      [applicationId, redirectHash, redirectUri],
    );
    const row = rows[0];
    return row ? { applicationId: row.application_id, redirectUri: row.redirect_uri, status: row.status } : null;
  }

  async saveApplicationLoginPolicy(applicationId, requiredPermission, auditEvent) {
    return this.#transaction(async (connection) => {
      await connection.execute(
        `INSERT INTO application_login_policies(application_id, required_permission, status)
         VALUES (?, ?, 'active')
         ON DUPLICATE KEY UPDATE required_permission = VALUES(required_permission), status = 'active'`,
        [applicationId, requiredPermission],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async getApplicationLoginPolicy(applicationId) {
    const [rows] = await this.pool.execute(
      `SELECT application_id, required_permission, status FROM application_login_policies
       WHERE application_id = ?`, [applicationId],
    );
    const row = rows[0];
    return row ? { applicationId: row.application_id, requiredPermission: row.required_permission, status: row.status } : null;
  }

  async saveApplicationAuthorizationCode(record, auditEvent) {
    return this.#transaction(async (connection) => {
      await connection.execute(
        `INSERT INTO application_authorization_codes(
           code_hash, identity_id, application_id, redirect_uri, code_challenge, issued_at, expires_at, consumed_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
        [record.codeHash, record.identityId, record.applicationId, record.redirectUri,
         record.codeChallenge, asMariaDate(record.issuedAt), asMariaDate(record.expiresAt)],
      );
      await this.#appendAudit(connection, auditEvent);
    });
  }

  async consumeApplicationAuthorizationCode({ codeHash, applicationId, redirectUri, codeChallenge, now = new Date() }, auditEvent) {
    return this.#transaction(async (connection) => {
      const [rows] = await connection.execute(
        `SELECT * FROM application_authorization_codes WHERE code_hash = ? FOR UPDATE`, [codeHash],
      );
      const row = rows[0];
      if (!row || row.consumed_at || row.application_id !== applicationId || row.redirect_uri !== redirectUri ||
          row.code_challenge !== codeChallenge || new Date(row.expires_at) <= now) return null;
      await connection.execute(
        "UPDATE application_authorization_codes SET consumed_at = ? WHERE code_hash = ?",
        [asMariaDate(now), codeHash],
      );
      await this.#appendAudit(connection, auditEvent);
      return {
        codeHash: row.code_hash, identityId: row.identity_id, applicationId: row.application_id,
        redirectUri: row.redirect_uri, codeChallenge: row.code_challenge,
        issuedAt: asIso(row.issued_at), expiresAt: asIso(row.expires_at), consumedAt: now.toISOString(),
      };
    });
  }

  async saveApplicationSession(record, auditEvent) {
    assertApplicationSessionAudit(record, auditEvent, "application_session.created");
    assertNewApplicationSessionRecord(record);
    return this.#transaction(async (connection) => {
      await connection.execute(
        `INSERT INTO application_sessions(
           session_id, secret_hash, identity_id, application_id, issued_at, last_seen_at,
           idle_expires_at, absolute_expires_at, authenticated_at, idle_ttl_ms,
           context_label, revoked_at, revoked_by_identity_id, revocation_reason, version
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '', ?)`,
        [record.sessionId, record.secretHash, record.identityId, record.applicationId,
         asMariaDate(record.issuedAt), asMariaDate(record.lastSeenAt),
         asMariaDate(record.idleExpiresAt), asMariaDate(record.absoluteExpiresAt),
         asMariaDate(record.authenticatedAt), record.idleTtlMs, record.contextLabel, record.version],
      );
      await this.#appendAudit(connection, auditEvent);
      return structuredClone(record);
    });
  }

  async getApplicationSession(sessionId) {
    const [rows] = await this.pool.execute(
      "SELECT * FROM application_sessions WHERE session_id = ?", [sessionId],
    );
    return mapApplicationSession(rows[0]);
  }

  async listApplicationSessions(identityId) {
    const [rows] = await this.pool.execute(
      `SELECT * FROM application_sessions WHERE identity_id = ?
       ORDER BY last_seen_at DESC, session_id`, [identityId],
    );
    return rows.map(mapApplicationSession);
  }

  async listAllApplicationSessions() {
    const [rows] = await this.pool.execute(
      `SELECT * FROM application_sessions
       ORDER BY last_seen_at DESC, session_id`,
    );
    return rows.map(mapApplicationSession);
  }

  async touchApplicationSession(record, expectedVersion) {
    if (record.version !== expectedVersion + 1) throw new Error("stale application session version");
    return this.#transaction(async (connection) => {
      const [rows] = await connection.execute(
        "SELECT * FROM application_sessions WHERE session_id = ? FOR UPDATE", [record.sessionId],
      );
      const previous = mapApplicationSession(rows[0]);
      if (!previous || previous.version !== expectedVersion) throw new Error("stale application session version");
      assertApplicationSessionImmutableContext(previous, record);
      assertApplicationSessionActivityProgress(previous, record);
      if (previous.revokedAt !== record.revokedAt ||
          previous.revokedByIdentityId !== record.revokedByIdentityId ||
          previous.revocationReason !== record.revocationReason || previous.revokedAt) {
        throw new Error("inactive application session cannot be touched");
      }
      const [result] = await connection.execute(
        `UPDATE application_sessions
         SET last_seen_at = ?, idle_expires_at = ?, version = ?
         WHERE session_id = ? AND version = ? AND revoked_at IS NULL
           AND last_seen_at < ? AND absolute_expires_at > ? AND idle_expires_at > ?`,
        [asMariaDate(record.lastSeenAt), asMariaDate(record.idleExpiresAt), record.version,
         record.sessionId, expectedVersion, asMariaDate(record.lastSeenAt),
         asMariaDate(record.lastSeenAt), asMariaDate(record.lastSeenAt)],
      );
      if (result.affectedRows !== 1) throw new Error("stale or inactive application session");
      return structuredClone(record);
    });
  }

  async revokeApplicationSession(record, expectedVersion, auditEvent) {
    return (await this.revokeApplicationSessions([{ record, expectedVersion, auditEvent }]))[0];
  }

  async revokeApplicationSessions(closures) {
    if (!Array.isArray(closures) || closures.length === 0) {
      throw new Error("application session closures are required");
    }
    const sessionIds = new Set();
    for (const { record, auditEvent } of closures) {
      if (!["application_session.revoked", "application_session.expired"].includes(auditEvent?.action)) {
        throw new Error("invalid application session closure audit");
      }
      assertApplicationSessionAudit(record, auditEvent, auditEvent.action);
      if (sessionIds.has(record.sessionId)) throw new Error("duplicate application session closure");
      sessionIds.add(record.sessionId);
    }
    const ordered = [...closures].sort((left, right) => left.record.sessionId.localeCompare(right.record.sessionId));
    return this.#transaction(async (connection) => {
      for (const { record, expectedVersion } of ordered) {
        const [rows] = await connection.execute(
          "SELECT * FROM application_sessions WHERE session_id = ? FOR UPDATE", [record.sessionId],
        );
        const previous = mapApplicationSession(rows[0]);
        if (!previous || previous.version !== expectedVersion || record.version !== expectedVersion + 1) {
          throw new Error("stale application session version");
        }
        assertApplicationSessionImmutableContext(previous, record);
        if (previous.lastSeenAt !== record.lastSeenAt || previous.idleExpiresAt !== record.idleExpiresAt) {
          throw new Error("application session activity is immutable during revocation");
        }
        if (previous.revokedAt || !record.revokedAt || !record.revocationReason) {
          throw new Error("invalid application session revocation");
        }
      }
      for (const { record, expectedVersion, auditEvent } of ordered) {
        const [result] = await connection.execute(
          `UPDATE application_sessions
           SET revoked_at = ?, revoked_by_identity_id = ?, revocation_reason = ?, version = ?
           WHERE session_id = ? AND version = ? AND revoked_at IS NULL`,
          [asMariaDate(record.revokedAt), record.revokedByIdentityId, record.revocationReason,
           record.version, record.sessionId, expectedVersion],
        );
        if (result.affectedRows !== 1) throw new Error("stale application session version");
        await this.#appendAudit(connection, auditEvent);
      }
      return ordered.map(({ record }) => structuredClone(record));
    });
  }

  async listAssignments(identityId, applicationId) {
    const [rows] = await this.pool.execute(
      `SELECT * FROM access_assignments WHERE subject_id = ? AND application_id = ?
       ORDER BY assignment_id`, [identityId, applicationId],
    );
    return rows.map((row) => ({
      assignmentId: row.assignment_id, subjectId: row.subject_id, applicationId: row.application_id,
      roleId: row.role_id, permissions: parseJson(row.permissions_json), scopeType: row.scope_type,
      scopeId: row.scope_id, conditions: parseJson(row.conditions_json), status: row.status,
      validFrom: row.valid_from, validUntil: row.valid_until, reason: row.reason,
      decidedBy: row.decided_by, inheritedFromGroup: row.inherited_from_group, version: row.version,
    }));
  }

  async listAllAssignments() {
    const [rows] = await this.pool.execute(
      `SELECT * FROM access_assignments
       ORDER BY subject_id, application_id, role_id, assignment_id`,
    );
    return rows.map((row) => ({
      assignmentId: row.assignment_id, subjectId: row.subject_id, applicationId: row.application_id,
      roleId: row.role_id, permissions: parseJson(row.permissions_json), scopeType: row.scope_type,
      scopeId: row.scope_id, conditions: parseJson(row.conditions_json), status: row.status,
      validFrom: row.valid_from, validUntil: row.valid_until, reason: row.reason,
      decidedBy: row.decided_by, inheritedFromGroup: row.inherited_from_group, version: row.version,
    }));
  }

  async receiveNotificationEvents(events, audits) {
    return this.#transaction(async (connection) => {
      let created = 0;
      let alreadyPresent = 0;
      for (const event of events) {
        const [rows] = await connection.execute(
          `SELECT event_hash FROM notification_events
           WHERE source_application_id = ? AND source_event_id = ? FOR UPDATE`,
          [event.sourceApplicationId, event.eventId],
        );
        if (rows.length) {
          if (rows[0].event_hash !== event.eventHash) {
            throw new NotificationIngressError("notification_event_identity_conflict", 409);
          }
          alreadyPresent += 1;
          continue;
        }
        const audit = audits.get(event.eventId);
        if (!audit) throw new Error("notification audit event is required");
        await connection.execute(
          `INSERT INTO notification_events(
             source_application_id, source_event_id, event_type, event_hash,
             task_id, site_id, actor_id, aggregate_id, payload_json,
             occurred_at, received_at, status, processing_attempts, available_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)`,
          [event.sourceApplicationId, event.eventId, event.eventType, event.eventHash,
           event.taskId, event.siteId, event.actorId, event.aggregateId,
           JSON.stringify(event.payload), asMariaDate(event.occurredAt),
           asMariaDate(event.receivedAt), asMariaDate(event.receivedAt)],
        );
        await this.#appendAudit(connection, audit);
        created += 1;
      }
      return { created, alreadyPresent };
    });
  }

  async claimNotificationEvents({ workerId, limit, now, leaseMs }) {
    return this.#transaction(async (connection) => {
      const safeLimit = Number(limit);
      if (!Number.isInteger(safeLimit) || safeLimit < 1 || safeLimit > 100) throw new Error("invalid notification claim limit");
      const staleBefore = new Date(now.valueOf() - leaseMs);
      const [rows] = await connection.execute(
        `SELECT * FROM notification_events
         WHERE ((status IN ('pending', 'retry') AND available_at <= ?)
           OR (status = 'processing' AND claimed_at <= ?))
         ORDER BY available_at, occurred_at, source_application_id, source_event_id
         LIMIT ${safeLimit} FOR UPDATE SKIP LOCKED`,
        [asMariaDate(now), asMariaDate(staleBefore)],
      );
      const claimed = [];
      for (const row of rows) {
        await connection.execute(
          `UPDATE notification_events SET status = 'processing',
             processing_attempts = processing_attempts + 1,
             claimed_at = ?, claimed_by = ?, last_error_code = NULL
           WHERE source_application_id = ? AND source_event_id = ?`,
          [asMariaDate(now), workerId, row.source_application_id, row.source_event_id],
        );
        claimed.push(mapNotificationEvent({
          ...row, status: "processing", processing_attempts: Number(row.processing_attempts) + 1,
          claimed_at: now, claimed_by: workerId, last_error_code: null,
        }));
      }
      return claimed;
    });
  }

  async completeNotificationEvent({ sourceApplicationId, eventId, workerId, processedAt }) {
    const [result] = await this.pool.execute(
      `UPDATE notification_events SET status = 'processed', claimed_at = NULL,
         claimed_by = NULL, processed_at = ?, last_error_code = NULL
       WHERE source_application_id = ? AND source_event_id = ?
         AND status = 'processing' AND claimed_by = ?`,
      [asMariaDate(processedAt), sourceApplicationId, eventId, workerId],
    );
    if (result.affectedRows !== 1) throw new Error("notification lease is not owned by worker");
  }

  async failNotificationEvent({
    sourceApplicationId, eventId, workerId, availableAt, errorCode, quarantined,
  }) {
    const [result] = await this.pool.execute(
      `UPDATE notification_events SET status = ?, available_at = ?, claimed_at = NULL,
         claimed_by = NULL, processed_at = NULL, last_error_code = ?
       WHERE source_application_id = ? AND source_event_id = ?
         AND status = 'processing' AND claimed_by = ?`,
      [quarantined ? "quarantined" : "retry", asMariaDate(availableAt), errorCode,
       sourceApplicationId, eventId, workerId],
    );
    if (result.affectedRows !== 1) throw new Error("notification lease is not owned by worker");
  }

  async getNotificationEvent(sourceApplicationId, eventId) {
    const [rows] = await this.pool.execute(
      `SELECT * FROM notification_events
       WHERE source_application_id = ? AND source_event_id = ?`,
      [sourceApplicationId, eventId],
    );
    return mapNotificationEvent(rows[0]);
  }

  async materializeNotificationResolution({
    event, policyVersion, resolutionHash, suppressed, notifications, externalDeliveries, resolvedAt, auditEvent,
  }) {
    return this.#transaction(async (connection) => {
      const [existing] = await connection.execute(
        `SELECT resolution_hash, internal_notification_count, blocked_external_delivery_count
         FROM notification_resolutions
         WHERE source_application_id = ? AND source_event_id = ? FOR UPDATE`,
        [event.sourceApplicationId, event.eventId],
      );
      if (existing.length) {
        if (existing[0].resolution_hash !== resolutionHash) {
          throw Object.assign(new Error("notification resolution conflict"), { code: "notification_resolution_conflict" });
        }
        return {
          created: false,
          notifications: Number(existing[0].internal_notification_count),
          externalDeliveriesBlocked: Number(existing[0].blocked_external_delivery_count),
        };
      }
      const [events] = await connection.execute(
        `SELECT event_hash, status FROM notification_events
         WHERE source_application_id = ? AND source_event_id = ? FOR UPDATE`,
        [event.sourceApplicationId, event.eventId],
      );
      if (!events.length || events[0].event_hash !== event.eventHash || events[0].status !== "processing") {
        throw Object.assign(new Error("notification event is not owned for processing"), { code: "notification_event_unavailable" });
      }
      const recipientIds = [...new Set(notifications.map((notification) => notification.recipientIdentityId))];
      if (recipientIds.length) {
        const placeholders = recipientIds.map(() => "?").join(", ");
        const [identities] = await connection.execute(
          `SELECT identity_id FROM identities WHERE status = 'active' AND identity_id IN (${placeholders}) FOR UPDATE`,
          recipientIds,
        );
        const activeIds = new Set(identities.map((identity) => identity.identity_id));
        if (recipientIds.some((identityId) => !activeIds.has(identityId))) {
          throw Object.assign(new Error("notification recipient identity is unavailable"), { code: "recipient_identity_unavailable" });
        }
      }
      await connection.execute(
        `INSERT INTO notification_resolutions(
           source_application_id, source_event_id, policy_version, resolution_hash, suppressed_json,
           internal_notification_count, blocked_external_delivery_count, resolved_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [event.sourceApplicationId, event.eventId, policyVersion, resolutionHash, JSON.stringify(suppressed),
         notifications.length, externalDeliveries.length, asMariaDate(resolvedAt)],
      );
      for (const notification of notifications) {
        await connection.execute(
          `INSERT INTO notifications(
             notification_id, source_application_id, source_event_id, recipient_identity_id,
             category, importance, title, message, context_application_id, context_resource_type,
             context_resource_id, occurred_at, created_at, read_at, archived_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
          [notification.notificationId, event.sourceApplicationId, event.eventId,
           notification.recipientIdentityId, notification.category, notification.importance,
           notification.title, notification.message, notification.contextApplicationId,
           notification.contextResourceType, notification.contextResourceId,
           asMariaDate(notification.occurredAt), asMariaDate(notification.createdAt)],
        );
      }
      for (const delivery of externalDeliveries) {
        await connection.execute(
          `INSERT INTO notification_external_deliveries(
             delivery_id, notification_id, channel, status, blocked_reason,
             processing_attempts, available_at, claimed_at, claimed_by, delivered_at, last_error_code, created_at
           ) VALUES (?, ?, ?, 'blocked', ?, 0, NULL, NULL, NULL, NULL, NULL, ?)`,
          [delivery.deliveryId, delivery.notificationId, delivery.channel,
           delivery.blockedReason, asMariaDate(delivery.createdAt)],
        );
      }
      await this.#appendAudit(connection, auditEvent);
      return { created: true, notifications: notifications.length, externalDeliveriesBlocked: externalDeliveries.length };
    });
  }

  async listNotifications(identityId, limit = 100) {
    const safeLimit = Number(limit);
    if (!Number.isInteger(safeLimit) || safeLimit < 1 || safeLimit > 200) throw new Error("invalid notification list limit");
    const [rows] = await this.pool.execute(
      `SELECT n.notification_id, n.source_application_id, a.display_name AS source_application_name,
         n.category, n.importance, n.title, n.message, n.context_application_id,
         n.context_resource_type, n.context_resource_id, n.occurred_at, n.created_at,
         n.read_at, n.archived_at
       FROM notifications n
       JOIN identities i ON i.identity_id = n.recipient_identity_id AND i.status = 'active'
       JOIN applications a ON a.application_id = n.source_application_id
       WHERE n.recipient_identity_id = ? AND n.archived_at IS NULL
       ORDER BY n.occurred_at DESC, n.notification_id DESC LIMIT ${safeLimit}`,
      [identityId],
    );
    return rows.map((row) => ({
      notificationId: row.notification_id, sourceApplicationId: row.source_application_id,
      sourceApplicationName: row.source_application_name, category: row.category,
      importance: row.importance, title: row.title, message: row.message,
      contextApplicationId: row.context_application_id, contextResourceType: row.context_resource_type,
      contextResourceId: row.context_resource_id, occurredAt: asIso(row.occurred_at),
      createdAt: asIso(row.created_at), readAt: asIso(row.read_at), archivedAt: asIso(row.archived_at),
    }));
  }

  async countUnreadNotifications(identityId) {
    const [rows] = await this.pool.execute(
      `SELECT COUNT(*) AS count FROM notifications n
       JOIN identities i ON i.identity_id = n.recipient_identity_id AND i.status = 'active'
       WHERE n.recipient_identity_id = ? AND n.read_at IS NULL AND n.archived_at IS NULL`,
      [identityId],
    );
    return Number(rows[0]?.count ?? 0);
  }

  async recordNotificationProcessingRun({
    status, startedAt, finishedAt, errorCode, claimed, processed, retried, quarantined,
  }) {
    const validErrorCode = typeof errorCode === "string" && /^[a-z][a-z0-9_:-]{0,79}$/.test(errorCode);
    if (!["succeeded", "failed"].includes(status) || !(startedAt instanceof Date) ||
        !(finishedAt instanceof Date) || finishedAt < startedAt ||
        (status === "failed") !== validErrorCode || (status === "succeeded" && errorCode !== null)) {
      throw new Error("invalid notification processing outcome");
    }
    const counts = [claimed, processed, retried, quarantined].map(Number);
    if (counts.some((value) => !Number.isInteger(value) || value < 0 || value > 100)) {
      throw new Error("invalid notification processing counts");
    }
    await this.pool.execute(
      `INSERT INTO notification_processing_state(
         consumer_id, last_started_at, last_finished_at, last_status, last_error_code,
         last_claimed, last_processed, last_retried, last_quarantined, version
       ) VALUES ('internal-materializer-v1', ?, ?, ?, ?, ?, ?, ?, ?, 1)
       ON DUPLICATE KEY UPDATE
         last_started_at = VALUES(last_started_at), last_finished_at = VALUES(last_finished_at),
         last_status = VALUES(last_status), last_error_code = VALUES(last_error_code),
         last_claimed = VALUES(last_claimed), last_processed = VALUES(last_processed),
         last_retried = VALUES(last_retried), last_quarantined = VALUES(last_quarantined),
         version = version + 1`,
      [asMariaDate(startedAt), asMariaDate(finishedAt), status, errorCode,
       counts[0], counts[1], counts[2], counts[3]],
    );
  }

  async getNotificationOperationsSnapshot(limit = 50) {
    const safeLimit = Number(limit);
    if (!Number.isInteger(safeLimit) || safeLimit < 1 || safeLimit > 100) {
      throw new Error("invalid notification operations limit");
    }
    const [eventRows, notificationRows, deliveryRows, suppressionRows, recentRows, processorRows] = await Promise.all([
      this.pool.execute(
        `SELECT COUNT(*) AS total,
           COALESCE(SUM(status = 'pending'), 0) AS pending,
           COALESCE(SUM(status = 'processing'), 0) AS processing,
           COALESCE(SUM(status = 'retry'), 0) AS retrying,
           COALESCE(SUM(status = 'processed'), 0) AS processed,
           COALESCE(SUM(status = 'quarantined'), 0) AS quarantined,
           MIN(CASE WHEN status IN ('pending', 'retry') THEN available_at END) AS oldest_available_at,
           MAX(received_at) AS last_received_at,
           MAX(processed_at) AS last_processed_at
         FROM notification_events`,
      ),
      this.pool.execute(
        `SELECT COUNT(*) AS total,
           COALESCE(SUM(read_at IS NULL AND archived_at IS NULL), 0) AS unread,
           COALESCE(SUM(archived_at IS NOT NULL), 0) AS archived
         FROM notifications`,
      ),
      this.pool.execute(
        `SELECT COUNT(*) AS total,
           COALESCE(SUM(status = 'blocked'), 0) AS blocked,
           COALESCE(SUM(status <> 'blocked'), 0) AS non_blocked,
           COALESCE(SUM(status = 'pending'), 0) AS pending,
           COALESCE(SUM(status = 'processing'), 0) AS processing,
           COALESCE(SUM(status = 'retry'), 0) AS retrying,
           COALESCE(SUM(status = 'delivered'), 0) AS delivered,
           COALESCE(SUM(status = 'quarantined'), 0) AS quarantined
         FROM notification_external_deliveries`,
      ),
      this.pool.execute(
        `SELECT
           COALESCE(SUM(CAST(JSON_UNQUOTE(JSON_EXTRACT(suppressed_json, '$.own_action')) AS UNSIGNED)), 0) AS own_action,
           COALESCE(SUM(CAST(JSON_UNQUOTE(JSON_EXTRACT(suppressed_json, '$.preferences')) AS UNSIGNED)), 0) AS preferences,
           COALESCE(SUM(CAST(JSON_UNQUOTE(JSON_EXTRACT(suppressed_json, '$.unlinked_identity')) AS UNSIGNED)), 0) AS unlinked_identity
         FROM notification_resolutions`,
      ),
      this.pool.execute(
        `SELECT source_application_id, source_event_id, policy_version, suppressed_json,
           internal_notification_count, blocked_external_delivery_count, resolved_at
         FROM notification_resolutions
         ORDER BY resolved_at DESC, source_application_id, source_event_id
         LIMIT ${safeLimit}`,
      ),
      this.pool.execute(
        `SELECT last_started_at, last_finished_at, last_status, last_error_code,
           last_claimed, last_processed, last_retried, last_quarantined, version
         FROM notification_processing_state
         WHERE consumer_id = 'internal-materializer-v1'`,
      ),
    ]);
    const events = eventRows[0][0] ?? {};
    const notifications = notificationRows[0][0] ?? {};
    const deliveries = deliveryRows[0][0] ?? {};
    const suppressions = suppressionRows[0][0] ?? {};
    const processor = processorRows[0][0] ?? null;
    const number = (value) => Number(value ?? 0);
    return {
      events: {
        total: number(events.total), pending: number(events.pending), processing: number(events.processing),
        retrying: number(events.retrying), processed: number(events.processed), quarantined: number(events.quarantined),
        oldestAvailableAt: asIso(events.oldest_available_at), lastReceivedAt: asIso(events.last_received_at),
        lastProcessedAt: asIso(events.last_processed_at),
      },
      notifications: {
        total: number(notifications.total), unread: number(notifications.unread), archived: number(notifications.archived),
      },
      externalDeliveries: {
        total: number(deliveries.total), blocked: number(deliveries.blocked), nonBlocked: number(deliveries.non_blocked),
        pending: number(deliveries.pending), processing: number(deliveries.processing), retrying: number(deliveries.retrying),
        delivered: number(deliveries.delivered), quarantined: number(deliveries.quarantined),
      },
      suppressions: {
        ownAction: number(suppressions.own_action), preferences: number(suppressions.preferences),
        unlinkedIdentity: number(suppressions.unlinked_identity),
      },
      processor: processor ? {
        status: processor.last_status, lastStartedAt: asIso(processor.last_started_at),
        lastFinishedAt: asIso(processor.last_finished_at), errorCode: processor.last_error_code,
        claimed: number(processor.last_claimed), processed: number(processor.last_processed),
        retried: number(processor.last_retried), quarantined: number(processor.last_quarantined),
        version: number(processor.version),
      } : { status: "never_run", lastStartedAt: null, lastFinishedAt: null, errorCode: null,
        claimed: 0, processed: 0, retried: 0, quarantined: 0, version: 0 },
      recentResolutions: recentRows[0].map((row) => ({
        sourceApplicationId: row.source_application_id, eventId: row.source_event_id,
        policyVersion: row.policy_version, suppressed: parseJson(row.suppressed_json),
        internalNotificationCount: number(row.internal_notification_count),
        blockedExternalDeliveryCount: number(row.blocked_external_delivery_count),
        resolvedAt: asIso(row.resolved_at),
      })),
    };
  }

  async markNotificationRead({ identityId, notificationId, readAt }) {
    const [result] = await this.pool.execute(
      `UPDATE notifications SET read_at = ?
       WHERE notification_id = ? AND recipient_identity_id = ? AND read_at IS NULL AND archived_at IS NULL
         AND EXISTS (SELECT 1 FROM identities i WHERE i.identity_id = ? AND i.status = 'active')`,
      [asMariaDate(readAt), notificationId, identityId, identityId],
    );
    return { changed: result.affectedRows === 1 };
  }

  async markAllNotificationsRead({ identityId, readAt }) {
    const [result] = await this.pool.execute(
      `UPDATE notifications SET read_at = ?
       WHERE recipient_identity_id = ? AND read_at IS NULL AND archived_at IS NULL
         AND EXISTS (SELECT 1 FROM identities i WHERE i.identity_id = ? AND i.status = 'active')`,
      [asMariaDate(readAt), identityId, identityId],
    );
    return { changed: Number(result.affectedRows) };
  }

  async verifyAuditChain() {
    const [rows] = await this.pool.execute(
      "SELECT event_payload_json, previous_hash, event_hash FROM audit_events ORDER BY sequence",
    );
    return verifyAuditChain(rows.map((row) => ({
      event: parseJson(row.event_payload_json), previousHash: row.previous_hash, eventHash: row.event_hash,
    })));
  }
}
