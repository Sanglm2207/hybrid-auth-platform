-- Existing accounts must also verify their email before logging in again.
ALTER TABLE app_users
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE app_users ADD COLUMN email_otp_hash VARCHAR(255);
ALTER TABLE app_users ADD COLUMN email_otp_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE app_users ADD COLUMN email_otp_resend_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE app_users ADD COLUMN email_otp_attempts INTEGER NOT NULL DEFAULT 0;
