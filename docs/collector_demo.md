# Collector live demo

Goal: show `audit/audit.so` sending events into the collector, then query SQLite live.

## One-time setup

From repo root:

```sh
bash scripts/demo_collector_setup.sh
```

This creates writable demo dirs:

- `/var/ldwatch` for `events.db`
- `/run/ldwatch` for `ldwatch.sock`

It also rebuilds `audit/audit.so` and `bin/collector`.

## Terminal 1 — start collector

```sh
./bin/collector
```

Expected log:

```txt
[socket] listening on /run/ldwatch/ldwatch.sock
```

## Terminal 2 — generate LD_AUDIT events

```sh
LD_AUDIT=./audit/audit.so ls /tmp
```

You should see `[ldwatch]` audit logs on stderr. The audit library also sends binary events to the collector socket.

## Query SQLite live

```sh
sqlite3 /var/ldwatch/events.db "SELECT id,pid,exe,so_path,mechanism,timestamp FROM so_events LIMIT 10;"
```

Optional prettier output:

```sh
sqlite3 /var/ldwatch/events.db ".headers on" ".mode column" "SELECT id,pid,exe,so_path,mechanism,timestamp FROM so_events LIMIT 10;"
```

## Stop

Press `Ctrl-C` in Terminal 1.
