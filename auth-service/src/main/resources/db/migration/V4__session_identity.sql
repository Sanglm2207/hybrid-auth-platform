ALTER TABLE app_users ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE app_users ADD COLUMN deactivated_at TIMESTAMP WITH TIME ZONE;
-- Preserve the legacy role column for compatibility; new authorization uses the normalized assignments below.
ALTER TABLE app_users ALTER COLUMN role SET DEFAULT 'USER';
CREATE TABLE identity_roles (name VARCHAR(32) PRIMARY KEY);
INSERT INTO identity_roles(name) VALUES ('USER'), ('ADMIN');
INSERT INTO identity_roles(name) SELECT DISTINCT role FROM app_users WHERE role NOT IN ('USER', 'ADMIN');
CREATE TABLE identity_role_permissions (
    role_name VARCHAR(32) NOT NULL REFERENCES identity_roles(name),
    permission VARCHAR(64) NOT NULL,
    PRIMARY KEY(role_name, permission)
);
INSERT INTO identity_role_permissions(role_name, permission) VALUES
('USER','profile:read'),('USER','profile:write'),('USER','sessions:read'),('USER','sessions:revoke'),
('USER','devices:read'),('USER','devices:revoke'),('USER','account:deactivate'),
('ADMIN','profile:read'),('ADMIN','profile:write'),('ADMIN','sessions:read'),('ADMIN','sessions:revoke'),
('ADMIN','devices:read'),('ADMIN','devices:revoke'),('ADMIN','account:deactivate'),('ADMIN','roles:manage');
CREATE TABLE identity_user_roles (
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    role_name VARCHAR(32) NOT NULL REFERENCES identity_roles(name),
    PRIMARY KEY(user_id,role_name)
);
INSERT INTO identity_user_roles(user_id,role_name) SELECT id,role FROM app_users;
CREATE TABLE identity_devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    user_agent VARCHAR(256) NOT NULL,
    last_ip VARCHAR(64) NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(user_id,device_id)
);
