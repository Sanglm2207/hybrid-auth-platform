ALTER TABLE app_users ADD COLUMN session_generation BIGINT NOT NULL DEFAULT 0;
CREATE TABLE identity_admin_guard (id INTEGER PRIMARY KEY);
INSERT INTO identity_admin_guard(id) VALUES (1);
CREATE TABLE identity_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    credential_revision BIGINT NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    device_id UUID NOT NULL,
    user_agent VARCHAR(256) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX identity_sessions_owner ON identity_sessions(user_id, revoked_at, expires_at);
CREATE TABLE identity_refresh_ledger (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES identity_sessions(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX identity_refresh_expiry ON identity_refresh_ledger(expires_at);
CREATE TABLE auth_outbox (
    id UUID PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    encrypted_payload TEXT NOT NULL,
    trace_id VARCHAR(36),
    state VARCHAR(16) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    available_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_code VARCHAR(64)
);
CREATE INDEX auth_outbox_pending ON auth_outbox(state, available_at);
CREATE TABLE security_audit_records (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    event VARCHAR(64) NOT NULL,
    actor UUID,
    target UUID,
    details TEXT NOT NULL,
    trace_id VARCHAR(36)
);
