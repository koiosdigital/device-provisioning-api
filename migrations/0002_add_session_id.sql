-- Migration: Add session_id column to track Stripe sessions and prevent replay attacks
-- Created: 2025-12-25

ALTER TABLE license_keys ADD COLUMN session_id TEXT;

CREATE INDEX idx_license_keys_session_id ON license_keys(session_id);
