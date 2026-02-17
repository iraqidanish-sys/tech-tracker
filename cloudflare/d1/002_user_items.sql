CREATE TABLE IF NOT EXISTS user_items (
  email TEXT NOT NULL,
  collection_name TEXT NOT NULL,
  item_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (email, collection_name, item_id)
);

CREATE INDEX IF NOT EXISTS idx_user_items_email_collection_updated
ON user_items(email, collection_name, updated_at DESC);
