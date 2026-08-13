-- Lot 46 — registre central de sessions, migration additive.
-- À exécuter uniquement sur la base Administration de préproduction après
-- sauvegarde vérifiée, avec l'identité DDL dédiée.

CREATE TABLE IF NOT EXISTS application_sessions (
  session_id CHAR(36) PRIMARY KEY,
  secret_hash CHAR(64) NOT NULL,
  identity_id CHAR(36) NOT NULL,
  application_id VARCHAR(100) NOT NULL,
  issued_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NOT NULL,
  idle_expires_at DATETIME(6) NOT NULL,
  absolute_expires_at DATETIME(6) NOT NULL,
  authenticated_at DATETIME(6) NOT NULL,
  idle_ttl_ms INT UNSIGNED NOT NULL,
  context_label VARCHAR(255) NOT NULL,
  revoked_at DATETIME(6),
  revoked_by_identity_id CHAR(36),
  revocation_reason VARCHAR(500) NOT NULL,
  version INT UNSIGNED NOT NULL,
  CONSTRAINT application_sessions_identity_fk FOREIGN KEY (identity_id) REFERENCES identities(identity_id),
  CONSTRAINT application_sessions_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT application_sessions_revoker_fk FOREIGN KEY (revoked_by_identity_id) REFERENCES identities(identity_id),
  CONSTRAINT application_sessions_secret_hash_format CHECK (secret_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT application_sessions_lifetime CHECK (
    authenticated_at <= issued_at AND issued_at <= last_seen_at
    AND last_seen_at < idle_expires_at AND idle_expires_at <= absolute_expires_at
  ),
  CONSTRAINT application_sessions_revocation CHECK (
    (revoked_at IS NULL AND revoked_by_identity_id IS NULL AND revocation_reason = '')
    OR (revoked_at IS NOT NULL AND revocation_reason <> '')
  ),
  CONSTRAINT application_sessions_version CHECK (version >= 1),
  UNIQUE KEY application_sessions_secret_hash (secret_hash),
  INDEX application_sessions_identity_state (identity_id, revoked_at, absolute_expires_at),
  INDEX application_sessions_application_state (application_id, revoked_at, absolute_expires_at)
) ENGINE=InnoDB;
