#!/bin/bash
# LD-Watch — Master Test Runner
# Runs all test layers in order: audit hooks → unit → integration
# Run from repo root: bash scripts/run_tests.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${YELLOW}[run_tests]${NC} $1"; }
ok() { echo -e "${GREEN}[run_tests]${NC} $1"; }
fail() { echo -e "${RED}[run_tests]${NC} $1"; }

TOTAL_PASS=0
TOTAL_FAIL=0

echo ""
echo "════════════════════════════════════════"
echo "  LD-Watch Test Suite"
echo "════════════════════════════════════════"
echo ""

# ── Layer 1: Audit hook tests ──────────────────────────────────────────────────
info "Layer 1 — Audit hook tests (scripts/test_audit.sh)"
if bash scripts/test_audit.sh; then
  ok "Layer 1 passed"
  TOTAL_PASS=$((TOTAL_PASS + 1))
else
  fail "Layer 1 failed"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

echo ""

# ── Layer 2: Go unit tests ─────────────────────────────────────────────────────
info "Layer 2 — Go unit tests (go test ./...)"
if go test ./... -v 2>&1; then
  ok "Layer 2 passed"
  TOTAL_PASS=$((TOTAL_PASS + 1))
else
  fail "Layer 2 failed (may be expected if collector/engine not built yet)"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

echo ""

# ── Layer 3: Integration tests ────────────────────────────────────────────────
# These are added progressively as phases complete
info "Layer 3 — Integration tests"

INTEGRATION_DIR="tests/integration"
if [ -d "$INTEGRATION_DIR" ] && [ -n "$(ls $INTEGRATION_DIR/*.sh 2>/dev/null)" ]; then
  for test_file in "$INTEGRATION_DIR"/*.sh; do
    info "Running $test_file..."
    if bash "$test_file"; then
      ok "$test_file passed"
      TOTAL_PASS=$((TOTAL_PASS + 1))
    else
      fail "$test_file failed"
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
  done
else
  info "No integration tests yet — added in Phase 3+"
fi

echo ""
echo "════════════════════════════════════════"
echo -e "  Total: ${GREEN}$TOTAL_PASS passed${NC} / ${RED}$TOTAL_FAIL failed${NC}"
echo "════════════════════════════════════════"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
  exit 1
fi
