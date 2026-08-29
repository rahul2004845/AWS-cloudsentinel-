-- CloudSentinel PostgreSQL baseline for an Amazon RDS PostgreSQL instance.
-- The application creates these core tables automatically; this file is useful
-- for controlled production migrations and database review.
CREATE TABLE IF NOT EXISTS logs (
  event_id TEXT PRIMARY KEY,
  timestamp TIMESTAMPTZ,
  event_name TEXT,
  event_source TEXT,
  log_type TEXT,
  user_name TEXT,
  user_arn TEXT,
  source_ip TEXT,
  region TEXT,
  account_id TEXT,
  threat_detected BOOLEAN DEFAULT FALSE,
  severity TEXT,
  doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_account_region ON logs(account_id, region);
CREATE INDEX IF NOT EXISTS idx_logs_threats ON logs(threat_detected, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  event_id TEXT,
  timestamp TIMESTAMPTZ,
  threat_name TEXT,
  attack_type TEXT,
  severity TEXT,
  affected_resource TEXT,
  email_status TEXT,
  doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, timestamp DESC);
