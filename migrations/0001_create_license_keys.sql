-- Migration: Create license_keys table
-- Created: 2025-12-25

CREATE TABLE IF NOT EXISTS license_keys (
    user_id TEXT NOT NULL,
    license_key TEXT NOT NULL PRIMARY KEY,
    key_type TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    redeemed_at INTEGER
);

CREATE INDEX idx_license_keys_user_id ON license_keys(user_id);
CREATE INDEX idx_license_keys_key_type ON license_keys(key_type);
CREATE INDEX idx_license_keys_used ON license_keys(used);
