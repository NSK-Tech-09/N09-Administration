import { canonicalJson, eventHash, verifyAuditChain } from "./audit.mjs";

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

  async getApplication(applicationId) {
    const [rows] = await this.pool.execute(
      "SELECT application_id, display_name, status, registration_policy FROM applications WHERE application_id = ?",
      [applicationId],
    );
    const row = rows[0];
    return row ? { applicationId: row.application_id, displayName: row.display_name, status: row.status, registrationPolicy: row.registration_policy } : null;
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

  async verifyAuditChain() {
    const [rows] = await this.pool.execute(
      "SELECT event_payload_json, previous_hash, event_hash FROM audit_events ORDER BY sequence",
    );
    return verifyAuditChain(rows.map((row) => ({
      event: parseJson(row.event_payload_json), previousHash: row.previous_hash, eventHash: row.event_hash,
    })));
  }
}
