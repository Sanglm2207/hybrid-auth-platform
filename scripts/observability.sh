#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-up}" in
  up)
    mkdir -p logs/telemetry
    docker compose -f compose.observability.yaml up -d
    echo 'Grafana: http://127.0.0.1:3001 (or GRAFANA_PORT); dashboard: Hybrid Auth / Hybrid Auth - P5 Observability'
    ;;
  down) GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-unused-for-lifecycle-command}" docker compose -f compose.observability.yaml down ;;
  status) GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-unused-for-lifecycle-command}" docker compose -f compose.observability.yaml ps ;;
  logs) GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-unused-for-lifecycle-command}" docker compose -f compose.observability.yaml logs --tail 100 -f ;;
  *) echo 'Usage: bash scripts/observability.sh [up|down|status|logs]' >&2; exit 1 ;;
esac
