#!/bin/bash
# LD-Watch — Audit Library Hook Tests
# Tests that each hook fires correctly before wiring up the collector.
# Run from the repo root: bash scripts/test_audit.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
AUDIT_LIB="./audit/audit.so"

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

# ── Build probe binary for symbind tests ──────────────────────────────────────
PROBE_SRC="tests/fixtures/probe.c"
PROBE_BIN="tests/fixtures/probe"

info "Compiling probe binary for symbol tests..."
if gcc -o "$PROBE_BIN" "$PROBE_SRC"; then
  info "Probe binary ready."
else
  fail "Could not compile probe binary — skipping symbol tests"
  PROBE_BIN=""
fi
echo ""

# ── Test 1: Library loads and la_version fires ─────────────────────────────────
info "Test 1 — la_version: audit library loads cleanly"
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep -q "audit library loaded"; then
  pass "la_version fired — library loaded successfully"
else
  fail "la_version did not fire. Output was: $OUTPUT"
fi

# ── Test 2: la_objopen fires on SO load ───────────────────────────────────────
info "Test 2 — la_objopen: detects shared object loads"
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep -q "\[ldwatch\] LOAD"; then
  pass "la_objopen fired — SO load events captured"
else
  fail "la_objopen did not fire"
fi

# ── Test 3: libc.so appears in load events ────────────────────────────────────
info "Test 3 — la_objopen: libc.so.6 appears in load events"
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep "LOAD" | grep -q "libc.so"; then
  pass "libc.so.6 detected in SO load events"
else
  fail "libc.so.6 not found in load events"
fi

# ── Test 4: la_objsearch fires ────────────────────────────────────────────────
info "Test 4 — la_objsearch: SO search events captured"
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep -q "\[ldwatch\] SEARCH"; then
  pass "la_objsearch fired — search events captured"
else
  fail "la_objsearch did not fire"
fi

# ── Test 5: LD_LIBRARY_PATH hijack is flagged ─────────────────────────────────
info "Test 5 — la_objsearch: LD_LIBRARY_PATH usage flagged"
mkdir -p /tmp/ldwatch_test_libs
OUTPUT=$(LD_LIBRARY_PATH=/tmp/ldwatch_test_libs LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep "SEARCH" | grep -q "LD_LIBRARY_PATH"; then
  pass "LD_LIBRARY_PATH usage detected in search events"
else
  fail "LD_LIBRARY_PATH not flagged in search events"
fi
rm -rf /tmp/ldwatch_test_libs

# ── Test 6: la_symbind64 fires on 'open' ──────────────────────────────────────
info "Test 6 — la_symbind64: critical symbol 'open' is tracked"
if [ -n "$PROBE_BIN" ]; then
  OUTPUT=$(LD_AUDIT=$AUDIT_LIB $PROBE_BIN 2>&1 >/dev/null)
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
  OUTPUT=$(LD_AUDIT=$AUDIT_LIB $PROBE_BIN 2>&1 >/dev/null)
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
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep "SYMBOL" | grep -q "strlen"; then
  fail "Non-critical symbol 'strlen' appeared — filter not working"
else
  pass "Non-critical symbols correctly filtered out"
fi

# ── Test 9: PID is logged in all events ───────────────────────────────────────
info "Test 9 — all events include pid"
OUTPUT=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null)
if echo "$OUTPUT" | grep -q "pid="; then
  pass "PID is present in event output"
else
  fail "PID missing from event output"
fi

# ── Test 10: multiple binaries produce separate events ────────────────────────
info "Test 10 — events fire independently per binary"
OUT1=$(LD_AUDIT=$AUDIT_LIB ls /tmp 2>&1 >/dev/null | grep "LOAD" | wc -l)
OUT2=$(LD_AUDIT=$AUDIT_LIB curl --version 2>&1 >/dev/null | grep "LOAD" | wc -l)
if [ "$OUT1" -gt 0 ] && [ "$OUT2" -gt 0 ]; then
  pass "Events fire for multiple different binaries (ls: $OUT1 SOs, curl: $OUT2 SOs)"
else
  fail "Events did not fire for one or more binaries"
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
