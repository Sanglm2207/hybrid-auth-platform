#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f keys/private.pem || ! -f keys/public.pem ]]; then
  bash ./generate-keys.sh
fi
if [[ -z "${JAVA_HOME:-}" && -x /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home
fi
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
source ./.env
if [[ -z "${JWT_KEY_SET:-}" ]]; then
  if [[ ! -f keys/jwt-key-set.json ]]; then
    python3 scripts/jwt-keys.py init --private-pem "${JWT_PRIVATE_KEY:-keys/private.pem}"
  fi
  printf '\nJWT_KEY_SET=./keys/jwt-key-set.json\n' >> .env
  echo 'Enabled JWT key manifest reload in .env (existing signing key preserved)'
fi
