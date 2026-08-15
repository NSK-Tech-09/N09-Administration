CREATE TABLE IF NOT EXISTS email_login_tokens (
  email_login_id CHAR(36) PRIMARY KEY,
  token_hash CHAR(64) NOT NULL UNIQUE,
  identity_id CHAR(36) NOT NULL,
  return_to VARCHAR(2048) NOT NULL,
  status VARCHAR(16) NOT NULL,
  requested_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6),
  invalidated_at DATETIME(6),
  CONSTRAINT email_login_identity_fk FOREIGN KEY (identity_id) REFERENCES identities(identity_id),
  CONSTRAINT email_login_hash CHECK (token_hash REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT email_login_status CHECK (status IN ('issued', 'consumed', 'delivery_failed')),
  CONSTRAINT email_login_validity CHECK (expires_at > requested_at),
  CONSTRAINT email_login_consumption CHECK (
    (status = 'issued' AND consumed_at IS NULL AND invalidated_at IS NULL)
    OR (status = 'consumed' AND consumed_at IS NOT NULL AND invalidated_at IS NULL)
    OR (status = 'delivery_failed' AND consumed_at IS NULL AND invalidated_at IS NOT NULL)
  ),
  INDEX email_login_identity_status_expiry (identity_id, status, expires_at)
) ENGINE=InnoDB;
