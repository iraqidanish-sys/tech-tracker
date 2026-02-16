CREATE TABLE IF NOT EXISTS user_snapshots (
  email TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'unknown',
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_user_snapshots_updated_at
ON user_snapshots(updated_at);

CREATE TABLE IF NOT EXISTS app_config (
  config_key TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
