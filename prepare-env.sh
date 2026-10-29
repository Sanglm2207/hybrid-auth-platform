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
