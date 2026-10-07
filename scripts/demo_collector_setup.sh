#!/usr/bin/env bash
set -euo pipefail

# Prepare writable runtime dirs for the live collector demo without modifying
# existing telemetry. Pass --reset only after stopping the collector.
# Run from repo root:
#   bash scripts/demo_collector_setup.sh

USER_NAME="${SUDO_USER:-${USER}}"
GROUP_NAME="$(id -gn "$USER_NAME")"
RUNTIME_DIR="/run/ldwatch"
DATA_DIR="/var/ldwatch"
SOCKET_PATH="$RUNTIME_DIR/ldwatch.sock"
DATABASE_PATH="$DATA_DIR/events.db"

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--reset" ]; }; then
  echo "Usage: $0 [--reset]" >&2
  exit 2
fi

sudo install -d -m 0775 -o "$USER_NAME" -g "$GROUP_NAME" "$DATA_DIR"
sudo install -d -m 0775 -o "$USER_NAME" -g "$GROUP_NAME" "$RUNTIME_DIR"

if [ "${1:-}" = "--reset" ]; then
  # An existing endpoint may belong to a live collector. Do not unlink it:
  # unlinking an active UNIX socket makes that collector unreachable.
  if [ -e "$SOCKET_PATH" ] || [ -L "$SOCKET_PATH" ]; then
    echo "Refusing to reset while $SOCKET_PATH exists. Stop the collector and remove a confirmed stale socket first." >&2
    exit 1
  fi

  if [ -e "$DATABASE_PATH" ]; then
    if ! command -v fuser >/dev/null 2>&1; then
      echo "Refusing to reset $DATABASE_PATH: fuser is required to check for an active collector." >&2
      exit 1
    fi
    if fuser -s "$DATABASE_PATH"; then
      echo "Refusing to reset $DATABASE_PATH because it is in use." >&2
      exit 1
    fi
    sudo rm -f -- "$DATABASE_PATH" "$DATABASE_PATH-shm" "$DATABASE_PATH-wal"
  fi
fi

make audit collector

cat <<EOF
Demo setup ready.

Existing telemetry was preserved. To reset demo data after stopping the collector:
  bash scripts/demo_collector_setup.sh --reset

Terminal 1:
  ./bin/collector

Terminal 2:
  LD_AUDIT=./audit/audit.so ls /tmp
  sqlite3 /var/ldwatch/events.db "SELECT id,process_key,pid,exe,event_type,subject_path,origin,timestamp FROM loader_events ORDER BY id LIMIT 10;"

If sqlite3 is missing:
  sudo apt-get update && sudo apt-get install -y sqlite3
EOF
