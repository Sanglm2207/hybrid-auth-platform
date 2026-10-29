ALTER TABLE app_users ADD COLUMN credential_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE app_users ADD COLUMN password_reset_resend_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE app_users ADD COLUMN email_change_resend_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE account_action_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    purpose VARCHAR(32) NOT NULL CHECK (purpose IN ('RESET_PASSWORD', 'CHANGE_EMAIL')),
    credential_revision BIGINT NOT NULL,
    target_email VARCHAR(254),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX account_tokens_user_purpose ON account_action_tokens(user_id, purpose);
CREATE INDEX account_tokens_expiry ON account_action_tokens(expires_at);
