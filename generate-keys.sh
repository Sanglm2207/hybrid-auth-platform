#!/usr/bin/env bash
set -euo pipefail
mkdir -p keys
if [[ -e keys/private.pem || -e keys/public.pem ]]; then echo "Keys exist; refusing overwrite"; exit 1; fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/private.pem
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem
