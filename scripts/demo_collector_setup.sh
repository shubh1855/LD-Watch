#!/usr/bin/env bash
set -euo pipefail

# Prepare writable runtime dirs for the live collector demo.
# Run from repo root:
#   bash scripts/demo_collector_setup.sh

USER_NAME="${SUDO_USER:-${USER}}"
GROUP_NAME="$(id -gn "$USER_NAME")"

sudo install -d -m 0775 -o "$USER_NAME" -g "$GROUP_NAME" /var/ldwatch
sudo install -d -m 0775 -o "$USER_NAME" -g "$GROUP_NAME" /run/ldwatch

rm -f /var/ldwatch/events.db /run/ldwatch/ldwatch.sock

make audit collector

cat <<EOF
Demo setup ready.

Terminal 1:
  ./bin/collector

Terminal 2:
  LD_AUDIT=./audit/audit.so ls /tmp
  sqlite3 /var/ldwatch/events.db "SELECT id,pid,exe,so_path,mechanism,timestamp FROM so_events LIMIT 10;"

If sqlite3 is missing:
  sudo apt-get update && sudo apt-get install -y sqlite3
EOF
