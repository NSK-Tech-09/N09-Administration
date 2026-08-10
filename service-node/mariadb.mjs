import { createHash, randomUUID } from "node:crypto";
import { canonicalJson, eventHash, verifyAuditChain } from "./audit.mjs";
import { externalPrincipalKey } from "./federated-identity.mjs";

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

  async verifyAuditChain() {
    const [rows] = await this.pool.execute(
      "SELECT event_payload_json, previous_hash, event_hash FROM audit_events ORDER BY sequence",
    );
    return verifyAuditChain(rows.map((row) => ({
      event: parseJson(row.event_payload_json), previousHash: row.previous_hash, eventHash: row.event_hash,
    })));
  }
}
