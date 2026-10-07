# Collector and detection demo

## Isolated end-to-end demo

From repository root on x86_64 Linux/glibc with GCC, Make, Go 1.26.1 and sqlite3:

```bash
LDWATCH_DEMO_DIR=/tmp/ldwatch-demo-review bash scripts/demo_t10.sh
```

Use a new directory. The script refuses an existing events.db or collector.sock.
Without LDWATCH_DEMO_DIR it uses a unique temporary directory and removes it on
exit. With an explicit directory it preserves results and stops the collector.
It builds all deliverables and uses a dedicated absolute endpoint/database.
It does not reset the system collector or delete an existing database.

The initial audited /bin/true run has no approved profile and produces coverage
alerts. The script profiles, approves and activates production version 1,
checks that the clean rerun adds no alerts, then loads one harmless deviation
library and checks one additional UNKNOWN_SO. It exports HIGH alerts.

## Verified output

Re-run on 2026-10-07, directory /tmp/ldwatch-t11-20261007:

```text
T10 demo passed
database: /tmp/ldwatch-t11-20261007/events.db
socket: /tmp/ldwatch-t11-20261007/collector.sock
report: /tmp/ldwatch-t11-20261007/report.json
alerts: 5 (clean baseline: 4)
```

The four initial MISSING_BASELINE alerts are expected and remain persisted after
approval. They do not mean the approved clean rerun failed. Load paths vary by
distribution. This host's selected baseline contained:

```text
approved /usr/bin/true (production) v1
LOAD /lib64/ld-linux-x86-64.so.2 required
LOAD /usr/lib/libc.so.6 required
LOAD <main> required
LOAD linux-vdso.so.1 required
```

Inspect a retained run (jq is optional):

```bash
bin/ldwatch-cli alerts --db /tmp/ldwatch-demo-review/events.db --severity HIGH
bin/ldwatch-cli baseline show --db /tmp/ldwatch-demo-review/events.db \
  --exe /usr/bin/true --environment-key production
bin/ldwatch-cli diff --db /tmp/ldwatch-demo-review/events.db \
  --source events --exe /usr/bin/true --environment-key production
jq 'length' /tmp/ldwatch-demo-review/report.json
jq 'map(.Rule) | group_by(.) | map({rule: .[0], count: length})' \
  /tmp/ldwatch-demo-review/report.json
jq '.[] | select(.Rule == "UNKNOWN_SO") | .Detail | fromjson' \
  /tmp/ldwatch-demo-review/report.json
```

Verified report summary:

```json
[
  {"rule": "MISSING_BASELINE", "count": 4},
  {"rule": "UNKNOWN_SO", "count": 1}
]
```

Report output is a top-level array. Detail is a JSON string, decoded above
using fromjson; report timestamps are Unix nanoseconds. Do not use .alerts.
Diff reports the retained libdeviation.so as UNEXPECTED and does not execute
a program.

Audit diagnostics are silent by default; the library sends binary events to
the collector independently. Confirm observations in SQLite or with the CLI.
Explicit diagnostics require an already nonblocking stderr pipe; see
[bounded logging policy](audit-logging.md).

Watch streams stored rows until interrupted:

```bash
bin/ldwatch-cli watch --db /tmp/ldwatch-demo-review/events.db --after 0
```

## Manual live collection in two terminals

Choose a private directory with no existing collector. Terminal 1:

```bash
make all
mkdir -m 700 /tmp/ldwatch-live-review
bin/collector --db /tmp/ldwatch-live-review/events.db \
  --socket /tmp/ldwatch-live-review/collector.sock --environment production
```

Terminal 2, from the same checkout:

```bash
LDWATCH_SOCKET=/tmp/ldwatch-live-review/collector.sock \
  LDWATCH_VERBOSE=0 LD_AUDIT="$PWD/audit/audit.so" /bin/true
sqlite3 /tmp/ldwatch-live-review/events.db \
  'SELECT id,process_key,pid,exe,event_type,subject_path,origin FROM loader_events ORDER BY id LIMIT 10;'
bin/ldwatch-cli alerts --db /tmp/ldwatch-live-review/events.db
```

To build a trusted profile, run baseline profile, inspect, approve and use,
each with the same --db, --exe /usr/bin/true and --environment-key production.
Use the version printed by approve. Review candidates before approving:
reprofiling after injection can teach an unwanted library. Ctrl-C stops the
collector; it does not remove the retained database.

Socket access is 0660, not world-writable. Both processes must have permission
to access the private parent and socket. Use audit/audit.so, not an object .o.
Sender LDWATCH_SOCKET must match the collector's absolute endpoint.

## Container workspace

```bash
docker compose build dev
docker compose run --rm dev
# Inside the container:
make all
LDWATCH_DEMO_DIR=/tmp/demo bash scripts/demo_t10.sh
```

The read-only source copy is used in tmpfs; outputs disappear on container exit.
For manual two-terminal use, both terminals must attach to the same running
container and use the same database/socket. Separate containers do not share
those paths by default. No writable host source mount, ptrace capability or
seccomp exception is required by these routine fixtures.

## Troubleshooting and scope

No telemetry: confirm .so built, collector running, endpoint matches, and
permissions allow connecting. Logs alone are not proof of persisted rows.
No tables: check the database path and container, rather than querying legacy
so_events as the current event table. Canonical events are in loader_events.

Load origin UNKNOWN is expected even for the harmless preload: the source
does not affirmatively establish mechanism. This demo validates UNKNOWN_SO,
not PRELOAD_PRIVILEGED, malware prevention or three packaged attack scenarios.
See [threat model](threat-model.md) and [T09 evidence](t09-evidence.md).
