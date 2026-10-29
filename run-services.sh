#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

bash ./prepare-env.sh
set -a
source ./.env
set +a

# Use the workspace JDK on macOS when JAVA_HOME has not been set.
if [[ -z "${JAVA_HOME:-}" && -x /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home
fi
if [[ -n "${JAVA_HOME:-}" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi
for tool in java mvn docker curl openssl python3; do
  command -v "$tool" >/dev/null || { echo "Missing required command: $tool" >&2; exit 1; }
done
java_version=$(java -version 2>&1)
if [[ ! "$java_version" =~ version\ \"25[.\"] ]]; then
  echo 'JDK 25 is required. Set JAVA_HOME to your JDK 25 installation.' >&2
  exit 1
fi

bash ./prepare-jwt.sh
set -a
source ./.env
set +a
docker compose up -d --wait postgres redis
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U auth -d authdb -f /docker-entrypoint-initdb.d/01-user-db.sql
mvn -B -ntp verify
mkdir -p logs

pids=()
cleanup() {
  trap - EXIT INT TERM
  if (( ${#pids[@]} )); then
    echo 'Stopping Java services...'
    kill "${pids[@]}" 2>/dev/null || true
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_service() {
  local module=$1 port=$2 pid attempt
  # Fail before launching if another process is already serving this port.
  if (echo >"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port is already in use ($module)." >&2
    exit 1
  fi
  SERVER_PORT=$port java --enable-native-access=ALL-UNNAMED -jar "$module/target/$module-1.0.0.jar" >"logs/$module.log" 2>&1 &
  pid=$!
  pids+=("$pid")
  for ((attempt=0; attempt<120; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "$module exited during startup:" >&2
      tail -n 40 "logs/$module.log" >&2
      exit 1
    fi
    if curl --fail --silent --max-time 2 "http://localhost:$port/actuator/health" >/dev/null; then
      echo "$module ready at http://localhost:$port (logs/$module.log)"
      return
    fi
    sleep 1
  done
  echo "Timed out waiting for $module. See logs/$module.log" >&2
  exit 1
}

start_service mail-service "${MAIL_SERVICE_PORT:-8703}"
start_service auth-service 8701
start_service user-service 8702
start_service api-gateway 8700
if [[ "${AUDIT_COLLECTOR_ENABLED:-true}" == true ]]; then
  collector_port=${AUDIT_COLLECTOR_PORT:-8710}
  if (echo >"/dev/tcp/127.0.0.1/$collector_port") 2>/dev/null; then
    echo "Audit collector port $collector_port is already in use." >&2; exit 1
  fi
  python3 scripts/audit-collector.py --port "$collector_port" >logs/audit-collector.log 2>&1 &
  collector_pid=$!; pids+=("$collector_pid")
  collector_ready=false
  for ((attempt=0; attempt<20; attempt++)); do
    kill -0 "$collector_pid" 2>/dev/null || { echo 'Audit collector failed; see logs/audit-collector.log' >&2; exit 1; }
    if curl --fail --silent --max-time 1 "http://127.0.0.1:$collector_port/health" >/dev/null; then collector_ready=true; break; fi
    sleep 1
  done
  [[ "$collector_ready" == true ]] || { echo 'Audit collector startup timed out' >&2; exit 1; }
  echo "Audit collector ready at http://127.0.0.1:$collector_port/metrics"
fi
echo 'All services ready. Gateway: http://localhost:8700 — press Ctrl+C to stop.'
while true; do
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo 'A Java service stopped unexpectedly. Check logs/.' >&2
      exit 1
    fi
  done
  sleep 1
done
