#!/usr/bin/env bash
set -euo pipefail

# Run a complete T10 demo in an isolated temporary database and socket.
# Set LDWATCH_DEMO_DIR to preserve a chosen output directory.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${LDWATCH_DEMO_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/ldwatch-demo.XXXXXX")}"
KEEP_DIR="${LDWATCH_DEMO_DIR:+1}"
DB_PATH="$DEMO_DIR/events.db"
SOCKET_PATH="$DEMO_DIR/collector.sock"
REPORT_PATH="$DEMO_DIR/report.json"
COLLECTOR_PID=""

cleanup() {
  if [ -n "$COLLECTOR_PID" ]; then
    kill -INT "$COLLECTOR_PID" 2>/dev/null || true
    wait "$COLLECTOR_PID" 2>/dev/null || true
  fi
  if [ -z "$KEEP_DIR" ]; then
    rm -rf -- "$DEMO_DIR"
  fi
}
trap cleanup EXIT INT TERM

die() { echo "demo: $*" >&2; exit 1; }
wait_for() {
  local query="$1" want="$2" label="$3" value
  for _ in $(seq 1 100); do
    value="$(sqlite3 "$DB_PATH" "PRAGMA busy_timeout=2000; $query" 2>/dev/null | tail -n 1 || true)"
    value="${value:-0}"
    [ "$value" -ge "$want" ] && return 0
    sleep 0.05
  done
  die "timed out waiting for $label (got $value, wanted >= $want)"
}

mkdir -p -- "$DEMO_DIR"
[ ! -e "$DB_PATH" ] || die "demo directory already contains events.db; choose a new directory"
[ ! -e "$SOCKET_PATH" ] || die "demo directory already contains collector.sock; choose a new directory"
command -v gcc >/dev/null || die "gcc is required"
command -v sqlite3 >/dev/null || die "sqlite3 is required"

make -C "$ROOT_DIR" all >/dev/null
cat >"$DEMO_DIR/deviation.c" <<'EOF'
__attribute__((constructor)) static void harmless_constructor(void) {}
EOF
gcc -shared -fPIC -O2 -o "$DEMO_DIR/libdeviation.so" "$DEMO_DIR/deviation.c"

"$ROOT_DIR/bin/collector" --db "$DB_PATH" --socket "$SOCKET_PATH" \
  --environment production >"$DEMO_DIR/collector.log" 2>&1 &
COLLECTOR_PID=$!
for _ in $(seq 1 100); do
  [ -S "$SOCKET_PATH" ] && break
  sleep 0.05
done
[ -S "$SOCKET_PATH" ] || die "collector socket did not start"

run_audited() {
  LD_AUDIT="$ROOT_DIR/audit/audit.so" \
  LDWATCH_SOCKET="$SOCKET_PATH" \
  LDWATCH_VERBOSE=0 "$@"
}

run_audited /bin/true
wait_for "SELECT COUNT(*) FROM loader_events" 1 "initial telemetry"
initial_alerts="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts")"

"$ROOT_DIR/bin/ldwatch-cli" baseline profile --db "$DB_PATH" \
  --exe /usr/bin/true --environment-key production >/dev/null
"$ROOT_DIR/bin/ldwatch-cli" baseline approve --db "$DB_PATH" \
  --exe /usr/bin/true --environment-key production >/dev/null
"$ROOT_DIR/bin/ldwatch-cli" baseline use --db "$DB_PATH" \
  --exe /usr/bin/true --environment-key production --version 1

run_audited /bin/true
wait_for "SELECT COUNT(*) FROM loader_events" 2 "clean rerun telemetry"
clean_alerts="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts")"
[ "$clean_alerts" = "$initial_alerts" ] || die "clean run created alerts ($initial_alerts -> $clean_alerts)"

LD_PRELOAD="$DEMO_DIR/libdeviation.so" run_audited /bin/true
wait_for "SELECT COUNT(*) FROM alerts WHERE rule='UNKNOWN_SO'" 1 "deviation alert"
deviation_alerts="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts")"
[ "$deviation_alerts" -eq $((clean_alerts + 1)) ] || die "deviation alert count mismatch"

"$ROOT_DIR/bin/ldwatch-cli" report --db "$DB_PATH" --output "$REPORT_PATH" --severity HIGH
grep -q 'UNKNOWN_SO' "$REPORT_PATH" || die "report missing UNKNOWN_SO"

echo "T10 demo passed"
echo "database: $DB_PATH"
echo "socket: $SOCKET_PATH"
echo "report: $REPORT_PATH"
echo "alerts: $deviation_alerts (clean baseline: $clean_alerts)"
