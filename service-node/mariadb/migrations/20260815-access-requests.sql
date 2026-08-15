-- Lot 62 — demandes publiques d'accès, migration additive et réversible applicativement.

CREATE TABLE IF NOT EXISTS access_requests (
  request_id CHAR(36) PRIMARY KEY,
  applicant_name VARCHAR(120) NOT NULL,
  applicant_email VARCHAR(320) NOT NULL,
  applicant_email_normalized VARCHAR(320) NOT NULL,
  reason VARCHAR(1000) NOT NULL,
  status VARCHAR(32) NOT NULL,
  requested_at DATETIME(6) NOT NULL,
  version INT UNSIGNED NOT NULL,
  CONSTRAINT access_requests_status CHECK (status IN ('pending', 'approved', 'partially_approved', 'refused')),
  CONSTRAINT access_requests_version CHECK (version >= 1),
  INDEX access_requests_status_time (status, requested_at),
  INDEX access_requests_email_status (applicant_email_normalized, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS access_request_lines (
  line_id CHAR(36) PRIMARY KEY,
  request_id CHAR(36) NOT NULL,
  application_id VARCHAR(100) NOT NULL,
  status VARCHAR(32) NOT NULL,
  target_identity_id CHAR(36),
  assignment_id CHAR(36),
  decided_at DATETIME(6),
  decided_by CHAR(36),
  decision_justification VARCHAR(500) NOT NULL,
  version INT UNSIGNED NOT NULL,
  CONSTRAINT access_request_lines_request_fk FOREIGN KEY (request_id) REFERENCES access_requests(request_id),
  CONSTRAINT access_request_lines_application_fk FOREIGN KEY (application_id) REFERENCES applications(application_id),
  CONSTRAINT access_request_lines_identity_fk FOREIGN KEY (target_identity_id) REFERENCES identities(identity_id),
  CONSTRAINT access_request_lines_assignment_fk FOREIGN KEY (assignment_id) REFERENCES access_assignments(assignment_id),
  CONSTRAINT access_request_lines_decider_fk FOREIGN KEY (decided_by) REFERENCES identities(identity_id),
  CONSTRAINT access_request_lines_status CHECK (status IN ('pending', 'approved', 'refused')),
  CONSTRAINT access_request_lines_version CHECK (version >= 1),
  CONSTRAINT access_request_lines_decision CHECK (
    (status = 'pending' AND target_identity_id IS NULL AND assignment_id IS NULL AND decided_at IS NULL AND decided_by IS NULL AND decision_justification = '')
    OR (status = 'approved' AND target_identity_id IS NOT NULL AND assignment_id IS NOT NULL AND decided_at IS NOT NULL AND decided_by IS NOT NULL AND decision_justification <> '')
    OR (status = 'refused' AND assignment_id IS NULL AND decided_at IS NOT NULL AND decided_by IS NOT NULL AND decision_justification <> '')
  ),
  UNIQUE KEY access_request_lines_application (request_id, application_id),
  INDEX access_request_lines_status_application (status, application_id)
) ENGINE=InnoDB;
