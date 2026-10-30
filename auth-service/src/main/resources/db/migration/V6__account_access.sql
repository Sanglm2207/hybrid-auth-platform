ALTER TABLE app_users ADD COLUMN admin_locked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE app_users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identity_devices ADD COLUMN trust_expires_at TIMESTAMP WITH TIME ZONE;
CREATE TABLE authentication_history (
 id UUID PRIMARY KEY, user_id UUID, occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
 successful BOOLEAN NOT NULL, reason VARCHAR(40) NOT NULL, ip VARCHAR(64) NOT NULL, user_agent VARCHAR(256) NOT NULL
);
CREATE INDEX authentication_history_owner ON authentication_history(user_id, occurred_at);
CREATE TABLE identity_api_keys (
 id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES app_users(id), name VARCHAR(100) NOT NULL,
 secret_hash VARCHAR(64) NOT NULL UNIQUE, scopes VARCHAR(512) NOT NULL,
 created_at TIMESTAMP WITH TIME ZONE NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
 revoked_at TIMESTAMP WITH TIME ZONE, last_used_at TIMESTAMP WITH TIME ZONE,
 credential_revision BIGINT NOT NULL, session_generation BIGINT NOT NULL
);
CREATE INDEX identity_api_keys_owner ON identity_api_keys(user_id);
CREATE TABLE identity_tenants (id UUID PRIMARY KEY, name VARCHAR(100) NOT NULL, owner_id UUID NOT NULL REFERENCES app_users(id));
CREATE TABLE identity_tenant_members (
 tenant_id UUID NOT NULL REFERENCES identity_tenants(id) ON DELETE CASCADE,
 user_id UUID NOT NULL REFERENCES app_users(id), PRIMARY KEY(tenant_id,user_id)
);
CREATE INDEX identity_tenant_member_user ON identity_tenant_members(user_id);
CREATE TABLE account_deletions (
 user_id UUID PRIMARY KEY REFERENCES app_users(id), requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
 completed_at TIMESTAMP WITH TIME ZONE, attempts INTEGER NOT NULL DEFAULT 0,
 available_at TIMESTAMP WITH TIME ZONE NOT NULL, state VARCHAR(16) NOT NULL
);
INSERT INTO identity_role_permissions(role_name,permission)
 SELECT 'USER',p FROM (VALUES ('account:delete'),('account:export'),('history:read'),('devices:trust'),('keys:manage'),('tokens:introspect')) AS t(p);
INSERT INTO identity_role_permissions(role_name,permission)
 SELECT 'ADMIN',p FROM (VALUES ('account:delete'),('account:export'),('history:read'),('devices:trust'),('keys:manage'),('tokens:introspect'),('users:read'),('users:update'),('tenants:manage')) AS t(p);
