CREATE TABLE reauthentication_proofs (
    proof_hash VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    credential_revision BIGINT NOT NULL,
    session_generation BIGINT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX reauthentication_proofs_owner ON reauthentication_proofs(user_id, session_id);
