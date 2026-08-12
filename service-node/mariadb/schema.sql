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

CREATE TABLE IF NOT EXISTS application_access_catalog_versions (
  application_id VARCHAR(100) NOT NULL,
  catalog_version INT UNSIGNED NOT NULL,
  catalog_hash CHAR(64) NOT NULL,
  roles_json JSON NOT NULL,
  permissions_json JSON NOT NULL,
  scope_types_json JSON NOT NULL,
  provisioning_json JSON NOT NULL,
  published_at DATETIME(6) NOT NULL,
  PRIMARY KEY (application_id, catalog_version),
  CONSTRAINT application_catalog_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT application_catalog_version CHECK (catalog_version >= 1),
  UNIQUE KEY application_catalog_hash (application_id, catalog_hash)
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

CREATE TABLE IF NOT EXISTS notification_events (
  source_application_id VARCHAR(100) NOT NULL,
  source_event_id VARCHAR(64) NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  event_hash CHAR(64) NOT NULL,
  task_id VARCHAR(64) NOT NULL,
  site_id VARCHAR(64) NOT NULL,
  actor_id VARCHAR(64),
  aggregate_id VARCHAR(64) NOT NULL,
  payload_json JSON NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  received_at DATETIME(6) NOT NULL,
  status VARCHAR(32) NOT NULL,
  processing_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  available_at DATETIME(6) NOT NULL,
  claimed_at DATETIME(6),
  claimed_by VARCHAR(128),
  processed_at DATETIME(6),
  last_error_code VARCHAR(80),
  PRIMARY KEY (source_application_id, source_event_id),
  CONSTRAINT notification_events_application_fk
    FOREIGN KEY (source_application_id) REFERENCES applications(application_id),
  CONSTRAINT notification_events_status CHECK (
    status IN ('pending', 'processing', 'retry', 'processed', 'quarantined')
  ),
  CONSTRAINT notification_events_claim CHECK (
    (status = 'processing' AND claimed_at IS NOT NULL AND claimed_by IS NOT NULL)
    OR (status <> 'processing' AND claimed_at IS NULL AND claimed_by IS NULL)
  ),
  CONSTRAINT notification_events_completion CHECK (
    (status = 'processed' AND processed_at IS NOT NULL)
    OR (status <> 'processed' AND processed_at IS NULL)
  ),
  CONSTRAINT notification_events_error CHECK (
    (status IN ('retry', 'quarantined') AND last_error_code IS NOT NULL)
    OR (status NOT IN ('retry', 'quarantined') AND last_error_code IS NULL)
  ),
  INDEX notification_events_available (status, available_at, occurred_at),
  INDEX notification_events_task (source_application_id, task_id, occurred_at),
  INDEX notification_events_site (source_application_id, site_id, occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notification_resolutions (
  source_application_id VARCHAR(100) NOT NULL,
  source_event_id VARCHAR(64) NOT NULL,
  policy_version VARCHAR(100) NOT NULL,
  resolution_hash CHAR(64) NOT NULL,
  suppressed_json JSON NOT NULL,
  internal_notification_count INT UNSIGNED NOT NULL,
  blocked_external_delivery_count INT UNSIGNED NOT NULL,
  resolved_at DATETIME(6) NOT NULL,
  PRIMARY KEY (source_application_id, source_event_id),
  CONSTRAINT notification_resolutions_event_fk FOREIGN KEY (source_application_id, source_event_id)
    REFERENCES notification_events(source_application_id, source_event_id),
  CONSTRAINT notification_resolutions_counts CHECK (
    internal_notification_count <= 1000 AND blocked_external_delivery_count <= 5000
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notifications (
  notification_id CHAR(64) PRIMARY KEY,
  source_application_id VARCHAR(100) NOT NULL,
  source_event_id VARCHAR(64) NOT NULL,
  recipient_identity_id CHAR(36) NOT NULL,
  category VARCHAR(80) NOT NULL,
  importance VARCHAR(32) NOT NULL,
  title VARCHAR(200) NOT NULL,
  message VARCHAR(1000) NOT NULL,
  context_application_id VARCHAR(100) NOT NULL,
  context_resource_type VARCHAR(80) NOT NULL,
  context_resource_id VARCHAR(128) NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  read_at DATETIME(6),
  archived_at DATETIME(6),
  UNIQUE KEY notifications_event_recipient (source_application_id, source_event_id, recipient_identity_id),
  CONSTRAINT notifications_resolution_fk FOREIGN KEY (source_application_id, source_event_id)
    REFERENCES notification_resolutions(source_application_id, source_event_id),
  CONSTRAINT notifications_recipient_fk FOREIGN KEY (recipient_identity_id) REFERENCES identities(identity_id),
  CONSTRAINT notifications_context_application_fk FOREIGN KEY (context_application_id) REFERENCES applications(application_id),
  CONSTRAINT notifications_importance CHECK (importance IN ('information', 'action', 'lifecycle', 'security')),
  INDEX notifications_recipient_created (recipient_identity_id, created_at),
  INDEX notifications_recipient_unread (recipient_identity_id, read_at, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notification_external_deliveries (
  delivery_id CHAR(64) PRIMARY KEY,
  notification_id CHAR(64) NOT NULL,
  channel VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  blocked_reason VARCHAR(80),
  processing_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  available_at DATETIME(6),
  claimed_at DATETIME(6),
  claimed_by VARCHAR(128),
  delivered_at DATETIME(6),
  last_error_code VARCHAR(80),
  created_at DATETIME(6) NOT NULL,
  UNIQUE KEY notification_external_delivery_channel (notification_id, channel),
  CONSTRAINT notification_external_delivery_notification_fk FOREIGN KEY (notification_id)
    REFERENCES notifications(notification_id),
  CONSTRAINT notification_external_delivery_channel_value CHECK (channel IN ('email', 'telegram', 'push', 'sms', 'whatsapp')),
  CONSTRAINT notification_external_delivery_status CHECK (status IN ('blocked', 'pending', 'processing', 'retry', 'delivered', 'quarantined')),
  CONSTRAINT notification_external_delivery_block CHECK (
    (status = 'blocked' AND blocked_reason IS NOT NULL) OR (status <> 'blocked' AND blocked_reason IS NULL)
  ),
  CONSTRAINT notification_external_delivery_claim CHECK (
    (status = 'processing' AND claimed_at IS NOT NULL AND claimed_by IS NOT NULL)
    OR (status <> 'processing' AND claimed_at IS NULL AND claimed_by IS NULL)
  ),
  CONSTRAINT notification_external_delivery_completion CHECK (
    (status = 'delivered' AND delivered_at IS NOT NULL)
    OR (status <> 'delivered' AND delivered_at IS NULL)
  ),
  CONSTRAINT notification_external_delivery_error CHECK (
    (status IN ('retry', 'quarantined') AND last_error_code IS NOT NULL)
    OR (status NOT IN ('retry', 'quarantined') AND last_error_code IS NULL)
  ),
  INDEX notification_external_delivery_available (status, available_at, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notification_processing_state (
  consumer_id VARCHAR(64) PRIMARY KEY,
  last_started_at DATETIME(6) NOT NULL,
  last_finished_at DATETIME(6) NOT NULL,
  last_status VARCHAR(32) NOT NULL,
  last_error_code VARCHAR(80),
  last_claimed INT UNSIGNED NOT NULL,
  last_processed INT UNSIGNED NOT NULL,
  last_retried INT UNSIGNED NOT NULL,
  last_quarantined INT UNSIGNED NOT NULL,
  version BIGINT UNSIGNED NOT NULL,
  CONSTRAINT notification_processing_state_consumer CHECK (consumer_id = 'internal-materializer-v1'),
  CONSTRAINT notification_processing_state_status CHECK (last_status IN ('succeeded', 'failed')),
  CONSTRAINT notification_processing_state_time CHECK (last_finished_at >= last_started_at),
  CONSTRAINT notification_processing_state_error CHECK (
    (last_status = 'failed' AND last_error_code IS NOT NULL)
    OR (last_status = 'succeeded' AND last_error_code IS NULL)
  ),
  CONSTRAINT notification_processing_state_counts CHECK (
    last_claimed <= 100 AND last_processed <= 100
    AND last_retried <= 100 AND last_quarantined <= 100
  )
) ENGINE=InnoDB;

CREATE TRIGGER IF NOT EXISTS notification_resolutions_no_update
BEFORE UPDATE ON notification_resolutions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notification resolutions are immutable';

CREATE TRIGGER IF NOT EXISTS notification_resolutions_no_delete
BEFORE DELETE ON notification_resolutions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notification resolutions are retained';

CREATE TRIGGER IF NOT EXISTS notifications_no_delete
BEFORE DELETE ON notifications FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notifications require an explicit retention policy';

CREATE TRIGGER IF NOT EXISTS notifications_payload_immutable
BEFORE UPDATE ON notifications FOR EACH ROW
BEGIN
  IF NEW.notification_id <> OLD.notification_id
    OR NEW.source_application_id <> OLD.source_application_id
    OR NEW.source_event_id <> OLD.source_event_id
    OR NEW.recipient_identity_id <> OLD.recipient_identity_id
    OR NEW.category <> OLD.category
    OR NEW.importance <> OLD.importance
    OR NEW.title <> OLD.title
    OR NEW.message <> OLD.message
    OR NEW.context_application_id <> OLD.context_application_id
    OR NEW.context_resource_type <> OLD.context_resource_type
    OR NEW.context_resource_id <> OLD.context_resource_id
    OR NEW.occurred_at <> OLD.occurred_at
    OR NEW.created_at <> OLD.created_at THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notification payload is immutable';
  END IF;
END;

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

CREATE TRIGGER IF NOT EXISTS notification_events_no_delete
BEFORE DELETE ON notification_events FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notification events are retained';

CREATE TRIGGER IF NOT EXISTS notification_events_payload_immutable
BEFORE UPDATE ON notification_events FOR EACH ROW
BEGIN
  IF NEW.source_application_id <> OLD.source_application_id
    OR NEW.source_event_id <> OLD.source_event_id
    OR NEW.event_type <> OLD.event_type
    OR NEW.event_hash <> OLD.event_hash
    OR NEW.task_id <> OLD.task_id
    OR NEW.site_id <> OLD.site_id
    OR NOT (NEW.actor_id <=> OLD.actor_id)
    OR NEW.aggregate_id <> OLD.aggregate_id
    OR NOT (NEW.payload_json <=> OLD.payload_json)
    OR NEW.occurred_at <> OLD.occurred_at
    OR NEW.received_at <> OLD.received_at THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'notification event payload is immutable';
  END IF;
END;
