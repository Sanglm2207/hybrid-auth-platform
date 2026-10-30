#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ $# != 1 ]]; then echo 'Usage: bash scripts/grant-admin.sh verified-account@example.com' >&2; exit 1; fi
# Explicit operator action; never runs automatically. CV invalidation also blocks existing refresh credentials.
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U auth -d authdb --set=admin_email="$1" <<'SQL'
BEGIN;
SELECT id FROM app_users WHERE email = lower(trim(:'admin_email')) AND active AND NOT admin_locked AND deleted_at IS NULL AND email_verified FOR UPDATE;
INSERT INTO identity_user_roles(user_id,role_name)
SELECT id, 'ADMIN' FROM app_users WHERE email = lower(trim(:'admin_email')) AND active AND NOT admin_locked AND deleted_at IS NULL AND email_verified
ON CONFLICT DO NOTHING;
UPDATE app_users SET credential_revision = credential_revision + 1
WHERE email = lower(trim(:'admin_email')) AND active AND NOT admin_locked AND deleted_at IS NULL AND email_verified;
COMMIT;
SQL
