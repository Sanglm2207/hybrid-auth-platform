#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f .env ]]; then
  (umask 077; cp .env.example .env)
  echo 'Created .env from .env.example'
fi

# Both the shell runner and VS Code use the same internal service credential.
# Never print it or replace a configured key.
source ./.env
if [[ -z "${MAIL_SERVICE_API_KEY:-}" ]]; then
  mail_service_key=$(openssl rand -hex 32)
  printf '\nMAIL_SERVICE_API_KEY=%s\n' "$mail_service_key" >> .env
  echo 'Configured an internal Mail service key in .env'
fi

if [[ -z "${AUTH_PROXY_KEY:-}" ]]; then
  auth_proxy_key=$(openssl rand -hex 32)
  printf '\nAUTH_PROXY_KEY=%s\n' "$auth_proxy_key" >> .env
  echo 'Configured an internal Gateway-to-Auth key in .env'
fi

if [[ -z "${IDENTITY_SERVICE_KEY:-}" ]]; then
  identity_service_key=$(openssl rand -hex 32)
  printf '\nIDENTITY_SERVICE_KEY=%s\n' "$identity_service_key" >> .env
  echo 'Configured an internal identity verification key in .env'
fi

if [[ -z "${MAIL_OUTBOX_ENCRYPTION_KEY:-}" ]]; then
  outbox_key=$(openssl rand -hex 32)
  printf '\nMAIL_OUTBOX_ENCRYPTION_KEY=%s\n' "$outbox_key" >> .env
  echo 'Configured encrypted outbox storage in .env'
fi
# Provision distinct runtime/migration credentials for upgraded local workspaces.
for credential in AUTH_APP_PASSWORD AUTH_MIGRATION_PASSWORD PROFILE_APP_PASSWORD MAIL_APP_PASSWORD MAIL_MIGRATION_PASSWORD; do
  if [[ -z "${!credential:-}" ]]; then
    generated_password=$(openssl rand -hex 32)
    printf '\n%s=%s\n' "$credential" "$generated_password" >> .env
    echo "Configured $credential in .env"
  fi
done
# Earlier P2 setup used the profile owner at runtime. Move only that known legacy default.
if [[ "${USER_DB_USERNAME:-}" == profiles ]]; then
  python3 - <<'MIGRATE_PROFILE_USER'
from pathlib import Path
import re
path = Path('.env')
path.write_text(re.sub(r'^USER_DB_USERNAME=profiles\s*$', 'USER_DB_USERNAME=profiles_app', path.read_text(), flags=re.MULTILINE))
MIGRATE_PROFILE_USER
  echo 'Updated the legacy profile runtime user to profiles_app'
fi
chmod 600 .env
