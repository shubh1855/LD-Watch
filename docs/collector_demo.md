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

Important:

- `LD_AUDIT` must point to `audit/audit.so`, not `audit/audit.o`
- if you changed socket or collector code, rebuild before testing
- the collector now creates `/run/ldwatch/ldwatch.sock` with permissions that allow non-root audited processes to connect

## Terminal 1 — start collector

```sh
./bin/collector
```

Expected log:

```txt
[socket] listening on /run/ldwatch/ldwatch.sock
```

If you prefer the full explicit form:

```sh
./bin/collector --db /var/ldwatch/events.db --socket /run/ldwatch/ldwatch.sock
```

## Terminal 2 — generate LD_AUDIT events

```sh
LD_AUDIT=./audit/audit.so ls /tmp
```

Audit diagnostics are silent by default; the library sends binary events to
the collector independently. Confirm observations in SQLite or with the CLI.
Explicit diagnostics require an already nonblocking stderr pipe; see
[bounded logging policy](audit-logging.md).

## Query SQLite live

```sh
sqlite3 /var/ldwatch/events.db "SELECT id,process_key,pid,exe,event_type,subject_path,origin,timestamp FROM loader_events ORDER BY id LIMIT 10;"
```

Optional prettier output:

```sh
sqlite3 /var/ldwatch/events.db ".headers on" ".mode column" "SELECT id,process_key,pid,exe,event_type,subject_path,origin,timestamp FROM loader_events ORDER BY id LIMIT 10;"
```

To verify the schema exists:

```sh
sqlite3 /var/ldwatch/events.db ".tables"
```

You should see `loader_events`, `process_instances`, baseline tables, and `alerts`. The old `so_events`, `symbol_events`, and `processes` tables contain legacy evidence only; see [T05 persistence](persistence.md).

## Docker flow

Use Docker only if both terminals attach to the same running container.

Example:

```sh
docker build -t ld-watch-dev ./docker
docker run -dit --name ldwatch-demo -v "$(pwd)":/ld-watch ld-watch-dev bash
docker exec -it ldwatch-demo bash
docker exec -it ldwatch-demo bash
```

Then inside container `ldwatch-demo`:

Terminal 1:

```sh
cd /ld-watch
make audit collector
mkdir -p /var/ldwatch /run/ldwatch
./bin/collector --db /var/ldwatch/events.db --socket /run/ldwatch/ldwatch.sock
```

Terminal 2:

```sh
cd /ld-watch
LD_AUDIT=./audit/audit.so ls /tmp
sqlite3 /var/ldwatch/events.db ".tables"
sqlite3 /var/ldwatch/events.db "SELECT id,process_key,pid,exe,event_type,subject_path,origin,timestamp FROM loader_events ORDER BY id LIMIT 10;"
```

Do not run the collector in one container and `LD_AUDIT` or `sqlite3` in another. Each container has its own `/run` and `/var`, so the socket and database will not be shared unless you explicitly mount them.

## Troubleshooting

If `LD_AUDIT=./audit/audit.o ...` fails:

```txt
ERROR: ld.so: object './audit/audit.o' cannot be loaded as audit interface
```

Use `audit/audit.so`. The `.o` file is not the loadable audit library.

If SQLite says:

```txt
Error: in prepare, no such table: so_events
```

That means the collector did not create or migrate the database you are querying. Common causes:

- the collector is not running
- the collector exited before you queried the DB
- you are querying the DB in a different Docker container than the collector
- you are looking at a newly created empty DB file

If you see audit stderr logs but no rows on the host machine:

- make sure you restarted the rebuilt `bin/collector`
- confirm the collector socket exists:

```sh
ls -l /run/ldwatch/ldwatch.sock
```

- confirm the socket is writable by the audited process, for example `srw-rw-rw-` or another mode that permits your user to connect

If you changed the audit header, IPC code, or collector:

```sh
make audit collector
```

## Stop

Press `Ctrl-C` in Terminal 1.
