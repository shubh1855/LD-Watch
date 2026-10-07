#!/bin/bash
# LD-Watch — Audit Library Hook Tests
# Tests that each hook fires correctly before wiring up the collector.
# Run from the repo root: bash scripts/test_audit.sh

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
AUDIT_LIB="./audit/audit.so"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ldwatch-audit.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

pass() {
  echo -e "${GREEN}[PASS]${NC} $1"
  PASS=$((PASS + 1))
}
fail() {
  echo -e "${RED}[FAIL]${NC} $1"
  FAIL=$((FAIL + 1))
}
info() { echo -e "${YELLOW}[info]${NC} $1"; }

# ── Preflight ──────────────────────────────────────────────────────────────────
info "Building audit library..."
make -C audit -s
if [ ! -f "$AUDIT_LIB" ]; then
  echo -e "${RED}audit.so not found. Build failed.${NC}"
  exit 1
fi
info "audit.so ready."
echo ""

LOGGING_BIN="$TEST_DIR/audit-logging"
gcc -Wall -Wextra -O2 -o "$LOGGING_BIN" tests/fixtures/audit_logging.c
diagnostics() {
  LDWATCH_VERBOSE=1 timeout 5 "$LOGGING_BIN" capture "$AUDIT_LIB" "$@"
}

info "Test 0d - default logging cannot block on a full stderr pipe"
if env -u LDWATCH_VERBOSE LDWATCH_SOCKET="$TEST_DIR/no-logging-collector.sock" \
  "$LOGGING_BIN" blocking "$AUDIT_LIB" /bin/true && \
  env -u LDWATCH_VERBOSE "$LOGGING_BIN" quiet "$AUDIT_LIB" /bin/true; then
  pass "default operation completes and emits no diagnostics"
else
  fail "default operation blocked or wrote diagnostics"
fi

info "Test 0e - explicit diagnostics are bounded for full, blocking, and closed pipes"
if LDWATCH_VERBOSE=1 "$LOGGING_BIN" full "$AUDIT_LIB" /bin/true && \
  LDWATCH_VERBOSE=1 "$LOGGING_BIN" blocking "$AUDIT_LIB" /bin/true && \
  LDWATCH_VERBOSE=1 "$LOGGING_BIN" closed "$AUDIT_LIB" /bin/true; then
  pass "diagnostics drop safely without changing stderr flags or terminating the process"
else
  fail "diagnostic output blocked or caused SIGPIPE"
fi
echo ""


# Test 0a: absent collector remains fail-open and bounded
info "Test 0a - audited application remains bounded when collector is absent"
MISSING_SOCKET="$TEST_DIR/no-collector.sock"
if timeout 3 env LDWATCH_SOCKET="$MISSING_SOCKET" LDWATCH_VERBOSE=0 \
  LD_AUDIT="$AUDIT_LIB" /bin/true >/dev/null 2>&1; then
  pass "application exited successfully with the collector absent"
else
  fail "application failed or blocked with the collector absent"
fi
echo ""

# ── Build probe binary for symbind tests ──────────────────────────────────────
info "Test 0b - bounded sends to a slow collector"
LIFECYCLE_SO="$TEST_DIR/lifecycle.so"
BACKPRESSURE_BIN="$TEST_DIR/backpressure-probe"
SLOW_RECEIVER_BIN="$TEST_DIR/slow-receiver"
if gcc -shared -fPIC -Wall -Wextra -O2 -o "$LIFECYCLE_SO" tests/fixtures/lifecycle_library.c && \
  gcc -Wall -Wextra -O2 -o "$BACKPRESSURE_BIN" tests/fixtures/backpressure_probe.c -ldl && \
  gcc -Wall -Wextra -O2 -o "$SLOW_RECEIVER_BIN" tests/fixtures/slow_receiver.c; then
  SLOW_SOCKET="$TEST_DIR/slow.sock"
  SLOW_READY="$TEST_DIR/slow.ready"
  timeout 7 "$SLOW_RECEIVER_BIN" "$SLOW_SOCKET" "$SLOW_READY" >"$TEST_DIR/slow.out" 2>&1 &
  SLOW_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$SLOW_SOCKET" ] && break
    sleep 0.01
  done
  if timeout 3 env LDWATCH_SOCKET="$SLOW_SOCKET" LDWATCH_VERBOSE=0 \
    LD_AUDIT="$AUDIT_LIB" "$BACKPRESSURE_BIN" "$LIFECYCLE_SO" >/dev/null 2>&1 && \
    [ -f "$SLOW_READY" ]; then
    pass "application completed while receiver accepted but did not read telemetry"
  else
    fail "application blocked or slow receiver fixture did not accept a connection"
  fi
  kill "$SLOW_PID" 2>/dev/null || true
  wait "$SLOW_PID" 2>/dev/null || true
else
  fail "could not build slow-collector fixtures"
fi
echo ""

info "Test 0c - reconnect after collector restart"
RESTART_PROBE="$TEST_DIR/restart-probe"
WIRE_RECEIVER_BIN="$TEST_DIR/restart-receiver"
if gcc -Wall -Wextra -O2 -o "$RESTART_PROBE" tests/fixtures/restart_probe.c -ldl && \
  gcc -Wall -Wextra -O2 -o "$WIRE_RECEIVER_BIN" tests/fixtures/wire_receiver.c; then
  RESTART_SOCKET="$TEST_DIR/restart.sock"
  timeout 4 "$WIRE_RECEIVER_BIN" "$RESTART_SOCKET" >"$TEST_DIR/first-receiver.out" 2>&1 &
  FIRST_RECEIVER_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$RESTART_SOCKET" ] && break
    sleep 0.01
  done
  LDWATCH_SOCKET="$RESTART_SOCKET" LDWATCH_VERBOSE=0 LD_AUDIT="$AUDIT_LIB" \
    "$RESTART_PROBE" "$LIFECYCLE_SO" >/dev/null 2>&1 &
  RESTART_PROBE_PID=$!
  if wait "$FIRST_RECEIVER_PID"; then
    for _ in $(seq 1 100); do
      [ ! -S "$RESTART_SOCKET" ] && break
      sleep 0.01
    done
    sleep 0.9
    timeout 4 "$WIRE_RECEIVER_BIN" "$RESTART_SOCKET" >"$TEST_DIR/second-receiver.out" 2>&1 &
    SECOND_RECEIVER_PID=$!
    for _ in $(seq 1 100); do
      [ -S "$RESTART_SOCKET" ] && break
      sleep 0.01
    done
    if wait "$RESTART_PROBE_PID" && wait "$SECOND_RECEIVER_PID" && \
      grep -q '^WIRE_OK ' "$TEST_DIR/second-receiver.out"; then
      pass "same audited process reconnected and delivered to the restarted endpoint"
    else
      fail "sender did not reconnect: $(cat "$TEST_DIR/second-receiver.out")"
    fi
  else
    kill "$RESTART_PROBE_PID" 2>/dev/null || true
    wait "$RESTART_PROBE_PID" 2>/dev/null || true
    fail "initial controlled receiver did not accept a record"
  fi
else
  fail "could not build collector-restart fixtures"
fi
echo ""

PROBE_SRC="tests/fixtures/probe.c"
PROBE_BIN="$TEST_DIR/probe"

info "Compiling probe binary for symbol tests..."
if gcc -o "$PROBE_BIN" "$PROBE_SRC"; then
  info "Probe binary ready."
else
  fail "Could not compile probe binary — skipping symbol tests"
  PROBE_BIN=""
fi
echo ""

# ── Test 0: Full-range formatter output ───────────────────────────────────────
info "Test 0 — audit formatters support full uint64 values"
FORMATTER_BIN="$TEST_DIR/formatters"
if gcc -Wall -Wextra -I./audit/include \
  -o "$FORMATTER_BIN" tests/fixtures/formatters.c audit/src/audit.c; then
  FORMATTER_OUTPUT=$(LDWATCH_VERBOSE=1 timeout 5 "$LOGGING_BIN" capture "" "$FORMATTER_BIN" | tail -n 2)
  if [ "$FORMATTER_OUTPUT" = $'18446744073709551615\n0xffffffffffffffff' ]; then
    pass "uint64 decimal and hexadecimal output is complete"
  else
    fail "formatter output was incomplete: $FORMATTER_OUTPUT"
  fi
else
  fail "Could not compile formatter test"
fi
echo ""

# ── Test 1: Library loads and la_version fires ─────────────────────────────────
info "Test 1 — la_version: audit library loads cleanly"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep -q "audit library loaded"; then
  pass "la_version fired — library loaded successfully"
else
  fail "la_version did not fire. Output was: $OUTPUT"
fi

# ── Test 2: la_objopen fires on SO load ───────────────────────────────────────
info "Test 2 — la_objopen: detects shared object loads"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep -q "\[ldwatch\] LOAD"; then
  pass "la_objopen fired — SO load events captured"
else
  fail "la_objopen did not fire"
fi

# ── Test 3: libc.so appears in load events ────────────────────────────────────
info "Test 3 — la_objopen: libc.so.6 appears in load events"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep "LOAD" | grep -q "libc.so"; then
  pass "libc.so.6 detected in SO load events"
else
  fail "libc.so.6 not found in load events"
fi

# ── Test 4: la_objsearch fires ────────────────────────────────────────────────
info "Test 4 — la_objsearch: SO search events captured"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep -q "\[ldwatch\] SEARCH"; then
  pass "la_objsearch fired — search events captured"
else
  fail "la_objsearch did not fire"
fi

# ── Test 5: LD_LIBRARY_PATH hijack is flagged ─────────────────────────────────
info "Test 5 — la_objsearch: LD_LIBRARY_PATH usage flagged"
TEST_LIBRARY_DIR="$TEST_DIR/libs"
mkdir -p "$TEST_LIBRARY_DIR"
OUTPUT=$(LD_LIBRARY_PATH="$TEST_LIBRARY_DIR" diagnostics ls /tmp)
if echo "$OUTPUT" | grep "SEARCH" | grep -q "LD_LIBRARY_PATH"; then
  pass "LD_LIBRARY_PATH usage detected in search events"
else
  fail "LD_LIBRARY_PATH not flagged in search events"
fi

# ── Test 6: la_symbind64 fires on 'open' ──────────────────────────────────────
info "Test 6 — la_symbind64: critical symbol 'open' is tracked"
if [ -n "$PROBE_BIN" ]; then
  OUTPUT=$(diagnostics "$PROBE_BIN")
  if echo "$OUTPUT" | grep "SYMBOL" | grep -q "open"; then
    pass "la_symbind64 fired for critical symbol 'open'"
  else
    fail "la_symbind64 did not fire for 'open'. Output: $(echo "$OUTPUT" | grep SYMBOL)"
  fi
else
  fail "Skipped — probe binary not available"
fi

# ── Test 7: la_symbind64 fires for 'read' ─────────────────────────────────────
info "Test 7 — la_symbind64: critical symbol 'read' is tracked"
if [ -n "$PROBE_BIN" ]; then
  OUTPUT=$(diagnostics "$PROBE_BIN")
  if echo "$OUTPUT" | grep "SYMBOL" | grep -q "read"; then
    pass "la_symbind64 fired for critical symbol 'read'"
  else
    fail "la_symbind64 did not fire for 'read'. Output: $(echo "$OUTPUT" | grep SYMBOL)"
  fi
else
  fail "Skipped — probe binary not available"
fi

# ── Test 8: non-critical symbols are NOT logged ───────────────────────────────
info "Test 8 — la_symbind64: non-critical symbols are ignored (no noise)"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep "SYMBOL" | grep -q "strlen"; then
  fail "Non-critical symbol 'strlen' appeared — filter not working"
else
  pass "Non-critical symbols correctly filtered out"
fi

# ── Test 9: PID is logged in all events ───────────────────────────────────────
info "Test 9 — all events include pid"
OUTPUT=$(diagnostics ls /tmp)
if echo "$OUTPUT" | grep -q "pid="; then
  pass "PID is present in event output"
else
  fail "PID missing from event output"
fi

# ── Test 10: multiple binaries produce separate events ────────────────────────
info "Test 10 — events fire independently per binary"
OUT1=$(diagnostics ls /tmp | grep "LOAD" | wc -l)
OUT2=$(diagnostics curl --version | grep "LOAD" | wc -l)
if [ "$OUT1" -gt 0 ] && [ "$OUT2" -gt 0 ]; then
  pass "Events fire for multiple different binaries (ls: $OUT1 SOs, curl: $OUT2 SOs)"
else
  fail "Events did not fire for one or more binaries"
fi

# ── Test 11: v1 packet reaches a controlled seqpacket receiver ────────────────
info "Test 11 — v1 wire record and custom endpoint"
WIRE_RECEIVER_BIN="$TEST_DIR/wire_receiver"
WIRE_SOCKET="$TEST_DIR/ldwatch.sock"
if gcc -Wall -Wextra -o "$WIRE_RECEIVER_BIN" tests/fixtures/wire_receiver.c; then
  timeout 5 "$WIRE_RECEIVER_BIN" "$WIRE_SOCKET" >"$TEST_DIR/wire.out" 2>&1 &
  RECEIVER_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$WIRE_SOCKET" ] && break
    sleep 0.01
  done
  if LDWATCH_SOCKET="$WIRE_SOCKET" LDWATCH_VERBOSE=0 LD_AUDIT="$AUDIT_LIB" \
    /bin/true >/dev/null 2>&1; then
    if wait "$RECEIVER_PID" && grep -q '^WIRE_OK ' "$TEST_DIR/wire.out"; then
      pass "v1 1024-byte record delivered over configured SOCK_SEQPACKET endpoint"
    else
      fail "controlled receiver rejected the v1 record: $(cat "$TEST_DIR/wire.out")"
    fi
  else
    fail "audited fixture failed while using the configured endpoint"
    kill "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
  fi
else
  fail "Could not compile controlled wire receiver"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────"
TOTAL=$((PASS + FAIL))
echo -e "Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC} / $TOTAL total"
echo "────────────────────────────────────"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
