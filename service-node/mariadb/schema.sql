CREATE TABLE IF NOT EXISTS identities (
  identity_id CHAR(36) PRIMARY KEY,
  email VARCHAR(320) NOT NULL,
  email_normalized VARCHAR(320) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  CONSTRAINT identities_status CHECK (status IN ('invited', 'active', 'suspended', 'disabled', 'archived', 'deleted'))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS external_identities (
  external_identity_id CHAR(36) PRIMARY KEY,
  identity_id CHAR(36) NOT NULL,
  issuer VARCHAR(512) NOT NULL,
  subject VARCHAR(512) NOT NULL,
  provider_key VARCHAR(100) NOT NULL,
  principal_hash CHAR(64) NOT NULL UNIQUE,
  status VARCHAR(32) NOT NULL,
  linked_at DATETIME(6) NOT NULL,
  CONSTRAINT external_identities_identity_fk FOREIGN KEY (identity_id) REFERENCES identities(identity_id),
  CONSTRAINT external_identities_status CHECK (status IN ('active', 'revoked')),
  INDEX external_identities_identity (identity_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS external_identity_link_requests (
  request_id CHAR(36) PRIMARY KEY,
  issuer VARCHAR(512) NOT NULL,
  subject VARCHAR(512) NOT NULL,
  provider_key VARCHAR(100) NOT NULL,
  email_hint VARCHAR(320),
  display_name_hint VARCHAR(255),
  requested_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  status VARCHAR(32) NOT NULL,
  target_identity_id CHAR(36),
  decided_by CHAR(36),
  decision_justification TEXT NOT NULL,
  CONSTRAINT link_requests_target_fk FOREIGN KEY (target_identity_id) REFERENCES identities(identity_id),
  CONSTRAINT link_requests_decider_fk FOREIGN KEY (decided_by) REFERENCES identities(identity_id),
  CONSTRAINT link_requests_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  CONSTRAINT link_requests_validity CHECK (expires_at > requested_at),
  INDEX link_requests_principal_status (issuer(191), subject(191), status, expires_at),
  INDEX link_requests_status_expiry (status, expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS applications (
  application_id VARCHAR(100) PRIMARY KEY,
  display_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  registration_policy VARCHAR(32) NOT NULL,
  CONSTRAINT applications_status CHECK (status IN ('active', 'maintenance', 'retired')),
  CONSTRAINT applications_registration CHECK (registration_policy IN ('closed', 'invitation', 'approval'))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS application_redirect_uris (
  application_id VARCHAR(100) NOT NULL,
  redirect_uri VARCHAR(2048) NOT NULL,
  redirect_uri_hash CHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  PRIMARY KEY (application_id, redirect_uri_hash),
  CONSTRAINT application_redirects_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT application_redirects_status CHECK (status IN ('active', 'revoked'))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS application_login_policies (
  application_id VARCHAR(100) PRIMARY KEY,
  required_permission VARCHAR(150) NOT NULL,
  status VARCHAR(32) NOT NULL,
  CONSTRAINT application_login_policy_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT application_login_policy_status CHECK (status IN ('active', 'disabled'))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS application_authorization_codes (
  code_hash CHAR(64) PRIMARY KEY,
  identity_id CHAR(36) NOT NULL,
  application_id VARCHAR(100) NOT NULL,
  redirect_uri VARCHAR(2048) NOT NULL,
  code_challenge CHAR(43) NOT NULL,
  issued_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6),
  CONSTRAINT application_codes_identity_fk FOREIGN KEY (identity_id) REFERENCES identities(identity_id),
  CONSTRAINT application_codes_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT application_codes_validity CHECK (expires_at > issued_at),
  INDEX application_codes_expiry (expires_at),
  INDEX application_codes_identity_application (identity_id, application_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS access_assignments (
  assignment_id CHAR(36) PRIMARY KEY,
  subject_id CHAR(36) NOT NULL,
  application_id VARCHAR(100) NOT NULL,
  role_id VARCHAR(100) NOT NULL,
  permissions_json JSON NOT NULL,
  scope_type VARCHAR(100),
  scope_id VARCHAR(255),
  conditions_json JSON NOT NULL,
  status VARCHAR(32) NOT NULL,
  valid_from DATETIME(6),
  valid_until DATETIME(6),
  reason TEXT NOT NULL,
  decided_by CHAR(36),
  inherited_from_group CHAR(36),
  version INT UNSIGNED NOT NULL,
  CONSTRAINT assignments_identity_fk FOREIGN KEY (subject_id) REFERENCES identities(identity_id),
  CONSTRAINT assignments_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT assignments_scope_pair CHECK ((scope_type IS NULL) = (scope_id IS NULL)),
  CONSTRAINT assignments_validity CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
  CONSTRAINT assignments_version CHECK (version >= 1),
  INDEX assignments_subject_application (subject_id, application_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_events (
  sequence BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_id CHAR(36) NOT NULL UNIQUE,
  correlation_id CHAR(36) NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  action VARCHAR(150) NOT NULL,
  result VARCHAR(50) NOT NULL,
  source VARCHAR(100) NOT NULL,
  event_payload_json JSON NOT NULL,
  previous_hash CHAR(64) NOT NULL,
  event_hash CHAR(64) NOT NULL UNIQUE,
  INDEX audit_correlation (correlation_id),
  INDEX audit_occurred_at (occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_chain_head (
  chain_id TINYINT UNSIGNED PRIMARY KEY,
  current_hash CHAR(64) NOT NULL,
  last_sequence BIGINT UNSIGNED,
  CONSTRAINT audit_chain_singleton CHECK (chain_id = 1),
  CONSTRAINT audit_chain_last_event_fk FOREIGN KEY (last_sequence) REFERENCES audit_events(sequence)
) ENGINE=InnoDB;

INSERT IGNORE INTO audit_chain_head(chain_id, current_hash, last_sequence)
VALUES (1, '', NULL);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit events are immutable';

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit events are immutable';
