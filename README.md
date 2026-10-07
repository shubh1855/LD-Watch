# LD-Watch

### A Real-Time Threat Detection Engine for Dynamic Linker Exploitation on Linux

> **Major Project — BE Computer Engineering**
> Mumbai University

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Team](#team)
- [Git Workflow](#git-workflow)
- [Project Phases](#project-phases)
- [Quick Start](#quick-start)
- [Building](#building)
- [Running](#running)
- [Testing](#testing)
- [Attack Scenario Validation](#attack-scenario-validation)
- [CLI Reference](#cli-reference)
- [Database Schema](#database-schema)
- [Alert Format](#alert-format)
- [Known Limitations](#known-limitations)
- [References](#references)

---

## Overview

Every time a program runs on Linux, the OS silently loads dozens of supporting
shared libraries in the background — in milliseconds, with no monitoring by
default. Attackers exploit this blind spot to inject malicious libraries into
legitimate processes, hijack trusted system programs, and steal credentials
without triggering traditional security tools.

**LD-Watch** sits inside the dynamic linker itself using the `LD_AUDIT`
interface for explicitly instrumented x86_64 Linux/glibc programs. It captures
confirmed loads and selected symbol bindings, compares complete observations
against an approved executable/environment baseline, and persists alerts for
unexpected paths or providers. Collection is bounded and can drop observations;
alerts are asynchronous.

---

## Problem Statement

Modern operating systems silently load shared components every time a program
runs — a process that happens in milliseconds and goes largely unmonitored.
Attackers exploit this blind spot to inject malicious code into legitimate
programs, hijack trusted system tools, and steal credentials without triggering
traditional security tools. Current solutions focus on files, network traffic,
and system calls; loader-level observation complements these approaches. This project builds
a real-time detection engine that sits inside the loading mechanism, tracks
exactly what gets loaded and from where, and raises an alert the moment
something unexpected appears.

---

## Objectives

**1. Dynamic Linker Telemetry**
Monitor explicitly instrumented dynamically linked Linux/glibc programs and
track loader searches, confirmed loads, selected bindings and object closes.
System-wide coverage remains a future objective.

**2. Baseline Deviation Detection**
Build a "what normal looks like" reference for common system programs, and
automatically raise an alert when something unexpected gets loaded — like a
known program suddenly pulling in a suspicious file from an unusual location.

**3. Symbol Interposition Detection**
Detect when a malicious component silently intercepts critical system functions
— the technique attackers use to steal credentials, hide processes, or tamper
with system behavior. Detection does not guarantee prevention before damage.

---

## How It Works

```
Normal program startup:

  bash → ld.so → loads libc.so, libdl.so, ... → runs

With LD-Watch:

  bash → ld.so → [LD_AUDIT hook fires] → audit.so captures event
                                        → sends to collector daemon
                                        → detection engine checks baseline
                                        → alert raised if deviation found
```

Think of `ld.so` as a delivery courier that fetches packages for every
program. `LD_AUDIT` is like assigning an inspector to ride along with that
courier and log every pickup. If the courier picks up something from a
suspicious location that wasn't on the original order, the inspector flags
it immediately. LD-Watch is that inspector.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Target Process                        │
│                                                              │
│   ld.so ──► [LD_AUDIT hook] ──► audit.so (C)                │
│                  │                                           │
│                  ├── la_objopen()     SO loaded              │
│                  ├── la_objsearch()   SO search path         │
│                  ├── la_symbind64()   symbol resolved        │
│                  └── la_objclose()    object closed          │
└──────────────────────────┬───────────────────────────────────┘
                           │ Unix socket (/run/ldwatch/ldwatch.sock)
                           │ 1,024-byte v1 seqpacket
                           ▼
             ┌─────────────────────────┐
             │    Collector Daemon     │  (Go)
             │  socket listener        │
             │  SQLite writer          │
             │  event dispatcher       │
             └────────────┬────────────┘
                          │
             ┌────────────▼────────────┐
             │    Detection Engine     │  (Go)
             │  Rule 1: Unknown SO     │
             │  Rule 2: Path Hijack    │
             │  Rule 3: Symbol Interp  │
             │  Baseline comparator    │
             └────────────┬────────────┘
                          │
             ┌────────────▼────────────┐
             │   SQLite Alert Store    │
             │  loader_events          │
             │  process_instances      │
             │  alerts                 │
             └────────────┬────────────┘
                          │
             ┌────────────▼────────────┐
             │     ldwatch-cli         │  (Go + flag)
             │  alerts / watch / diff  │
             └─────────────────────────┘
```

### IPC Protocol

The audit library and collector use AF_UNIX/SOCK_SEQPACKET with one explicitly
serialized 1,024-byte little-endian v1 record per packet. Header: LDW1,
version 1, length 1024. SEARCH=1, LOAD=2, SYMBOL_BIND=3, OBJECT_CLOSE=4.
See [protocol](docs/protocol.md) and the normative [wire offsets](docs/contract.md#wire-record).

Records carry PID and separate TID, process start ticks, namespace, timestamps,
symbol address, source executable, subject/provider, requester and symbol.
Text truncation and unresolved identity are explicit flags. Unknown bits and
nonzero reserved bytes are rejected; legacy 408-byte packets are incompatible.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | magic LDW1 |
| 4 | 2 | version 1 |
| 6 | 2 | record length 1024 |
| 8 | 1 | event type |
| 9 | 1 | origin |
| 10 | 2 | flags |
| 12 | 4 | PID |
| 16 | 4 | TID |
| 20 | 8 | process start ticks |
| 28 | 8 | namespace ID |
| 36 | 8 | Unix timestamp nanoseconds |
| 44 | 8 | resolved symbol address |
| 52 | 12 | reserved zero bytes |
| 64 | 256 | executable path |
| 320 | 384 | subject/provider path |
| 704 | 256 | related/requester path |
| 960 | 64 | symbol |

Default endpoint is `/run/ldwatch/ldwatch.sock`. An absolute sender
`LDWATCH_SOCKET` must match collector `--socket`. Sends are nonblocking and
bounded, with reconnect/fork handling; unavailable collectors may lose events.
LOAD origin normally remains UNKNOWN, including harmless preload deviations.

### Detection Rules

Rules consume complete LOAD or SYMBOL_BIND evidence, not search candidates.
PATH_HIJACK requires one unambiguous same-name approved path; ambiguous cases
remain UNKNOWN_SO. Missing/unresolved records do not certify a clean process.


| Rule                 | Trigger                                      | Severity |
| -------------------- | -------------------------------------------- | -------- |
| UNKNOWN_SO           | SO not in baseline for this binary           | HIGH     |
| PATH_HIJACK          | SO name matches baseline but path differs    | CRITICAL |
| SYMBOL_INTERPOSITION | Critical symbol resolves outside expected SO | CRITICAL |
| MISSING_BASELINE     | No approved baseline selected for the executable | HIGH |

`PRELOAD_PRIVILEGED` is deferred: current telemetry cannot prove preload
origin and privilege context.

---

## Tech Stack

| Component    | Language       | Why                                                   |
| ------------ | -------------- | ----------------------------------------------------- |
| `audit/`     | C              | LD_AUDIT is a C interface — mandatory                 |
| `cmd/collector/` | Go             | Goroutines make concurrent socket+DB trivial          |
| `internal/engine/` | Go             | Clean rule composition, easy to extend                |
| `cmd/ldwatch-cli/` | Go + flag     | Single binary, great flag/subcommand support          |
| Storage      | SQLite         | No server dependency, portable, fast enough           |
| Container    | Docker         | Isolated safe environment for attack scenario testing |
| CI           | GitHub Actions | Build/test on main/dev pushes and targeted PRs                  |

> **Note on C/Go boundary:** There is no CGo anywhere in this project.
> The C audit library and Go daemon are separate processes that communicate
> over a Unix socket. The boundary is pure IPC — not language interop.

---

## Repository Structure

```text
LD-Watch/
├── audit/
│   ├── src/{audit.c,hooks.c,ipc.c}    # callbacks, lifecycle, v1 sender
│   ├── include/audit.h
│   └── Makefile
├── cmd/
│   ├── collector/main.go            # daemon flags and workers
│   └── ldwatch-cli/{main.go,main_test.go}
├── internal/
│   ├── collector/processor.go       # persistence + connected rules
│   ├── engine/
│   │   ├── rules/{unknown_so.go,path_hijack.go,symbol_interpose.go}
│   │   ├── baseline/profiler.go     # candidates/approval
│   │   └── {engine.go,alert.go}
│   ├── identity/library.go          # shared canonical identities
│   ├── proto/event.go               # v1 decoder/validation
│   ├── socket/listener.go           # bounded seqpacket listener
│   └── store/                       # SQLite, queries/sqlc, migrations
├── tests/
│   ├── fixtures/                    # C source/receiver/lifecycle probes
│   └── integration/                 # Go integration and benchmarks
├── scripts/
│   ├── setup.sh
│   ├── demo_collector_setup.sh
│   ├── demo_t10.sh                  # isolated clean/deviation demo
│   ├── test_audit.sh
│   └── run_tests.sh
├── docs/
│   ├── {architecture.md,protocol.md,contract.md,threat-model.md}
│   ├── {collector_demo.md,persistence.md,references.md}
│   ├── {issues.md,fixes.md,pending-tasks.md}
│   └── {t09-evidence.md,t11-evidence.md}
├── docker/Dockerfile                # Ubuntu 24.04 / Go 1.26.1
├── docker-compose.yml               # read-only source/root + tmpfs
├── .github/workflows/ci.yml
├── {go.mod,go.sum,Makefile}
└── README.md
```

---

## Team

| Member   | Component         | Responsibilities                                |
| -------- | ----------------- | ----------------------------------------------- |
| Member 1 | `audit/`          | C library, all LD_AUDIT hooks, IPC sender       |
| Member 2 | `cmd/collector/` + `internal/store/` | Go daemon, SQLite schema, socket receiver       |
| Member 3 | `internal/engine/` | Detection rules, baseline profiler, alert store |
| Member 4 | `cmd/ldwatch-cli/` + `tests/` | CLI tool, all test layers, attack scenarios     |

> Everyone reviews PRs outside their own area. No merging your own PR.

---

## Git Workflow

### Branches

- `main` — released integration branch; team policy requires passing CI and PR review.
  Remote check on 2026-10-07 found branch protection disabled; protection is a
  repository-owner follow-up, not an enforced guarantee.
- `dev` — optional integration branch. The original workflow targets it first;
  recent task PRs also target main directly. CI covers both destinations.
- Feature branches — named as `feature/<component>-<what>`:
  - `feature/audit-hooks`
  - `feature/detection-rules`
  - `feature/cli-alerts`

### Commit Format

```
[component] short description

Examples:
[audit] add la_symbind64 hook
[engine] implement path hijack rule
[cli] add alerts subcommand with severity filter
[tests] add symbol interposition attack scenario
```

### PR Rules

- Every PR needs at least one review from a teammate outside your component
- No force pushes anywhere
- Squash commits before merging into `dev`
- `dev` → `main` only after all tests pass on CI

---

## Project Phases

| Phase | What                                        | Owner          | Target Week |
| ----- | ------------------------------------------- | -------------- | ----------- |
| 1     | Setup — repo, Docker, Makefile, CI skeleton | All            | 1           |
| 2     | Audit C library + IPC sender                | Member 1       | 2–3         |
| 3     | Collector daemon + SQLite                   | Member 2       | 4–5         |
| 4     | Detection engine + baseline profiler        | Member 3       | 6–7         |
| 5     | CLI tool                                    | Member 4       | 8           |
| 6     | Unit + integration + attack scenario tests  | Member 4 + all | 9–10        |
| 7     | CI pipeline, cleanup, demo prep             | All            | 11–12       |

### Phase Checklist

The original phase plan is retained below, updated to current implementation.
See [ordered tasks](docs/pending-tasks.md) and [T11 evidence](docs/t11-evidence.md)
for detailed acceptance and remaining limits.


**Phase 1 — Setup**

- [x] Repo created, all members have access
- [ ] Enable branch protection on `main` (disabled at the 2026-10-07 check)
- [ ] Fresh full Docker build/run evidence (Compose configuration validates)
- [x] Top-level `Makefile` targets defined: `all`, `audit`, `collector`, `cli`, `test`, `clean`
- [x] `go.mod` initialized
- [ ] Revalidate setup on a fresh Ubuntu host; script pins the aligned Go toolchain
- [x] GitHub Actions CI skeleton runs on push

**Phase 2 — Audit Library**

- [x] `la_version()` returns `LAV_CURRENT`
- [x] `la_objopen()` fires and logs SO path + PID
- [x] `la_objsearch()` captures `LA_SER_LIBPATH` flag (LD_LIBRARY_PATH used)
- [x] `la_symbind64()` captures symbol name + resolved address
- [x] IPC sender serializes explicit v1 packets to the Unix socket
- [x] Smoke test: `LD_AUDIT=./audit/audit.so ls` prints expected SOs

**Phase 3 — Collector Daemon**

- [x] Listens on `/run/ldwatch/ldwatch.sock`
- [x] Validates and decodes explicit v1 packets (real C-to-Go coverage)
- [x] Writes LOAD records to canonical `loader_events` (legacy `so_events` retained)
- [x] Writes SYMBOL_BIND records to `loader_events` (legacy symbol table retained)
- [x] Passes complete observations to connected approved-baseline rules
- [x] Handles concurrent processes with bounded queues and explicit degradation
- [ ] Universal no-drop guarantee (outside the bounded fail-open design)

**Phase 4 — Detection Engine**

- [x] Baseline profiler runs in learn mode and stores expected SO sets
- [x] Rule 1: UNKNOWN_SO fires correctly
- [x] Rule 2: PATH_HIJACK fires correctly
- [x] Rule 3: SYMBOL_INTERPOSITION fires correctly
- [ ] `PRELOAD_PRIVILEGED` is deferred until trustworthy origin and privilege metadata are available
- [x] Alerts written to `alerts` table with correct severity and JSON detail

**Phase 5 — CLI**

- [x] `ldwatch-cli alerts` lists recent alerts
- [x] `ldwatch-cli alerts --severity CRITICAL` filters correctly
- [x] `bin/ldwatch-cli baseline show --exe /usr/bin/curl --environment-key production`
- [x] `bin/ldwatch-cli watch --pid <pid>` polls persisted event rows
- [x] `bin/ldwatch-cli diff --source events --exe /usr/bin/ssh --environment-key production`
- [x] `bin/ldwatch-cli report --output report.json` exports alert report

**Phase 6 — Testing**

- [x] All unit tests pass: `go test ./... -v`
- [x] Clean approved-baseline processor/CLI integration and real T10 demo pass
- [x] Path-hijack rule/processor tests pass (synthetic evidence)
- [x] Harmless real LD_PRELOAD deviation generates UNKNOWN_SO in T10 demo
- [ ] Attack scenario 1 (LD_PRELOAD rootkit) detected
- [ ] Attack scenario 2 (path hijack) detected
- [ ] Attack scenario 3 (symbol interposition) detected

**Phase 7 — CI + Demo**

- [x] Complete main CI passed for the T10 merge (see T11 evidence)
- [ ] Docker demo environment runs all three attack scenarios end to end
- [x] Report output generated cleanly for viva demo

---

## Quick Start

Requirements: x86_64 Linux/glibc, GCC, Make and Go 1.26.1; sqlite3 for the
demo, jq optionally for reports. Docker uses Ubuntu 24.04 and the same Go
version. Review setup.sh's package/system changes before installing.

```bash
# Clone the repo
git clone https://github.com/shubh1855/LD-Watch.git
cd LD-Watch

# Review/install Ubuntu dependencies and Go 1.26.1
bash scripts/setup.sh

# Build everything
make all

# Run all tests
make test
```

---

## Building

Deliverables are audit/audit.so, bin/collector and bin/ldwatch-cli. The C audit
library communicates with Go through IPC, not CGo.

### Build everything

```bash
make all
```

### Build components individually

```bash
# Audit C library only
make audit
# Output: audit/audit.so

# Collector daemon only
make collector
# Output: bin/collector

# CLI only
make cli
# Output: bin/ldwatch-cli
```

### Using Docker (recommended for attack scenario testing)

```bash
# Build the container
docker build -t ld-watch-dev ./docker

# Use read-only host source and a disposable tmpfs workspace
docker compose build dev
docker compose run --rm dev

# Inside the container
make all
make test
```

---

## Running

Recommended first run: `bash scripts/demo_t10.sh`. It uses a private database
and socket, needs no sudo, and verifies baseline/clean/deviation/report behavior.
For retained results and manual two-terminal commands see
[the demo guide](docs/collector_demo.md). The system-path example below requires
appropriate database/socket directory and group permissions (socket mode 0660).


### Isolated demo with retained output

```bash
LDWATCH_DEMO_DIR=/tmp/ldwatch-demo-review bash scripts/demo_t10.sh
bin/ldwatch-cli alerts --db /tmp/ldwatch-demo-review/events.db --severity HIGH
bin/ldwatch-cli baseline show --db /tmp/ldwatch-demo-review/events.db \
  --exe /usr/bin/true --environment-key production
```

Choose a fresh directory. Existing database/socket paths are rejected.
Without LDWATCH_DEMO_DIR the unique temporary directory is removed on exit;
with it the output remains and the collector stops. A clean rerun must add
zero alerts; the harmless deviation adds one UNKNOWN_SO.

### Step 1 — Start the collector daemon

```bash
sudo ./bin/collector --db /var/ldwatch/events.db --socket /run/ldwatch/ldwatch.sock --environment production
```

### Step 2 — Run a program under LD-Watch

```bash
LD_AUDIT=$(pwd)/audit/audit.so curl https://example.com
```

### Step 3 — Check for alerts

```bash
./bin/ldwatch-cli alerts
```

### Running in baseline learn mode

```bash
# Build a candidate profile from events already recorded by the collector
./bin/ldwatch-cli baseline profile --exe /usr/bin/curl --environment-key production

# Review the executable-scoped candidate, then approve and activate it
./bin/ldwatch-cli baseline inspect --exe /usr/bin/curl --environment-key production
./bin/ldwatch-cli baseline approve --exe /usr/bin/curl --environment-key production
./bin/ldwatch-cli baseline use --exe /usr/bin/curl --environment-key production --version 1
```

`profile` incrementally reads only complete, source-identified `LOAD` and
`SYMBOL_BIND` records from the collector database (`/var/ldwatch/events.db` by
default). Candidate observations are scoped by executable and the explicit
environment label. Approval freezes a numbered version; `use` selects which
approved version detection should reload. Pass `--library /absolute/path.so --optional`
to `approve` to allow that exact load to be absent. Provider identity uses the
canonical full path; a basename match alone is not accepted. Reloading
without a selected approved version returns the explicit `MISSING_BASELINE`
error. Learning after approval creates or extends candidate observations and
cannot alter the approved version. Use the actual version printed by approval.
Do not profile/approve the injected demo observations as trusted production
normality. Collector --environment must match --environment-key; workers must
be positive (default 4). Unknown/truncated identity stays uncertain.

---

## Testing

### Unit Tests

Some paths below originated in the phase plan. Current executable equivalents
are shown; Go integration tests live in `tests/integration`, not shell files.


**Audit C library hook smoke tests**

```bash
bash scripts/test_audit.sh
```

These verify that `la_objopen` fires correctly and that known SOs appear
in the output for common binaries.

```bash
# What the script checks:
LD_AUDIT=./audit/audit.so ls / 2>&1 | grep -q "libc.so" && echo PASS || echo FAIL
LD_AUDIT=./audit/audit.so ls / 2>&1 | grep -q "libdl.so" && echo PASS || echo FAIL
```

**Go unit tests — collector + detection engine**

```bash
go test ./... -v
```

Covers:

- Store tests — SQLite writes, migrations, busy/full rollback and restart
- `TestUnknownSORuleFiresForUnknownSO` — unknown SO triggers HIGH alert
- `TestPathHijackRuleFiresForWrongPath` — wrong path triggers CRITICAL alert
- `TestSymbolInterpositionRuleFiresForWrongSO` — wrong provider triggers CRITICAL alert

### Integration Tests

**Test 1 — Clean binary, no alerts expected**

```bash
go test ./cmd/ldwatch-cli -run TestCleanAndDeviationAlertsReachCLIReport -v
```

Verifies clean/deviation observations through the processor and CLI report.
The real `/bin/true` demo also verifies no new alerts after baseline approval;
its initial MISSING_BASELINE alerts remain historical evidence.

**Test 2 — LD_LIBRARY_PATH path hijack**

```bash
go test ./internal/engine/rules -run TestPathHijackRuleFiresForWrongPath -v
go test ./internal/collector -run TestProcessorEvaluatesApprovedBaseline -v
```

Current rule/processor tests cover same-name different-path loads with controlled
records. The originally planned shell test is not present; a packaged real
LD_LIBRARY_PATH scenario remains future fixture work.

**Test 3 — LD_PRELOAD injection**

```bash
bash scripts/demo_t10.sh
```

Compiles a minimal shared object, injects it via `LD_PRELOAD`, verifies
`UNKNOWN_SO` alert is generated.

### CI and evidence

CI builds all deliverables, checks artifacts, runs Go race tests, vet and C
fixtures, and uploads outputs. It runs on pushes to main/dev and PRs targeting
those branches. [The T10 merge run](https://github.com/shubh1855/LD-Watch/actions/runs/37483536116)
passed; [T11 evidence](docs/t11-evidence.md) distinguishes remote CI from local
validation. The isolated demo is not a separate CI stage.

```bash
go test -race ./...
go vet ./...
docker compose config
```

### Run all test layers

```bash
make test
# or
bash scripts/run_tests.sh
```

---

## Attack Scenario Validation

The following scenarios map the original threat examples to current runnable
validation. Tests establish the stated evidence; packaged rootkit/credential
stealer payloads are not present. [T09 evidence](docs/t09-evidence.md) records
the real-source fixtures and measured workloads.

### Scenario 1 — LD_PRELOAD Injection / Rootkit Technique

A rootkit can inject a shared library through LD_PRELOAD. The current benign
demo compiles an empty constructor library and preloads it into /bin/true,
demonstrating unexpected-library detection without a malicious payload.

```bash
LDWATCH_DEMO_DIR=/tmp/ldwatch-preload-review bash scripts/demo_t10.sh
bin/ldwatch-cli alerts --db /tmp/ldwatch-preload-review/events.db --severity HIGH
```

Expected: four initial MISSING_BASELINE alerts before approval, no new alerts
for the approved clean rerun, and exactly one additional UNKNOWN_SO for
libdeviation.so. The source reports origin unknown; PRELOAD_PRIVILEGED remains
deferred because affirmative preload/privilege evidence is unavailable.

### Scenario 2 — LD_LIBRARY_PATH Path Hijack

The threat is a same-name library loaded from an unexpected directory.
Current rule and connected processor tests check wrong-path comparisons:

```bash
go test ./internal/engine/rules -run TestPathHijackRuleFiresForWrongPath -v
go test ./internal/collector -run TestProcessorEvaluatesApprovedBaseline -v
```

Expected rule: PATH_HIJACK, severity CRITICAL, when there is exactly one
same-name approved path. Ambiguous approved names remain UNKNOWN_SO.
These are controlled record tests, not a packaged real LD_LIBRARY_PATH
attack simulation; that additional live fixture remains future work.

### Scenario 3 — Symbol Interposition / Credential-Stealer Technique

Interposition can redirect a tracked critical symbol to an unexpected provider.
The current rule and processor tests verify provider identity and persistence:

```bash
go test ./internal/engine/rules -run TestSymbolInterpositionRuleFiresForWrongSO -v
go test ./internal/collector -run TestProcessorEvaluatesApprovedBaseline -v
bash scripts/test_audit.sh
```

Expected rule: SYMBOL_INTERPOSITION, severity CRITICAL, for a binding with a
different approved provider. The audit suite separately verifies real critical
symbol callbacks. Together these establish callback and rule evidence, not a
packaged live credential-stealing payload. Symbol coverage is limited to the
critical set in audit/include/audit.h and approved provider expectations.

---

## CLI Reference

Use `bin/ldwatch-cli` from repository root, or install it on PATH for the
unprefixed commands below. Pass --db after each command/subcommand. Watch polls
stored rows rather than subscribing directly to loader callbacks; diff does
not execute the target and supports --since-id to restrict observations.

```bash
# Show all recent alerts
ldwatch-cli alerts

# Filter by severity
ldwatch-cli alerts --severity CRITICAL
ldwatch-cli alerts --severity HIGH

# Show an active approved baseline
ldwatch-cli baseline show --exe /bin/curl --environment-key production

# Stream live events for a process
ldwatch-cli watch --pid 1234

# Compare recorded LOAD observations with an active approved baseline
ldwatch-cli diff --source events --exe /usr/bin/ssh --environment-key production

# Export alert report
ldwatch-cli report --output report.json
ldwatch-cli report --output report.json --since 2025-01-01
ldwatch-cli report --output report.json --since 2025-01-01 --until 2025-02-01
ldwatch-cli report --output report.json --severity HIGH
```

`diff` permits every approved optional library when present and reports MISSING
only for absent required loads. A tracked symbol can have multiple approved
providers; any canonical path in that set is accepted. An outside provider
triggers SYMBOL_INTERPOSITION, and alert detail lists the approved providers.

All commands accept `--db PATH` (default `/var/ldwatch/events.db`). Alert severity
filters accept `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. Report dates accept
`YYYY-MM-DD` or RFC3339 timestamps; `--since` is inclusive and `--until` is
exclusive. `watch` prints each event's stable database row ID and process key;
resume it with `--after ID`, and use `--pid` to filter a PID while retaining
the process-instance key in output. `diff --source events` explicitly selects
persisted loader observations as its comparison input.

`alerts` defaults to the newest 100 rows; `--limit` accepts 1–10,000.
`report` has no row-count cap: severity/date filters are applied in SQLite,
and all matching alerts are read from one consistent snapshot, ordered by
timestamp descending and ID. Inserts after that snapshot begins are not part
of the export. `--output -` (the default) writes JSON to stdout.

---

## Database Schema

Current events share a typed loader_events table rather than separate current
load/symbol tables. Legacy so_events, symbol_events and imported rows remain
archival evidence; they do not train approved profiles. Versioned migrations
preserve uncertainty and reject invalid migration histories.

| Table | Current purpose and identity |
| --- | --- |
| process_instances | process_key, PID, start ticks, executable/source status, first/last seen |
| loader_events | row ID, process key, PID/TID, executable, type, origin, flags, namespace, paths, symbol/address, timestamp, peer credentials |
| baseline_candidates | executable/environment/type/identity/symbol and observation count |
| baseline_versions | numbered approved/candidate/retired versions and metadata |
| baseline_entries | version-scoped LOAD or SYMBOL_PROVIDER identities with optionality |
| baseline_active | executable/environment selection of an approved baseline ID |
| baseline_learning_cursors | incremental learning cursor per executable/environment |
| baseline_candidate_policies | candidate optionality policy |
| alerts | UUID ID, rule/severity, process key, executable, JSON detail, timestamp, unique deduplication key |

The current alert table definition (migration 005) is:

```sql
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    rule TEXT NOT NULL CHECK(rule IN
        ('UNKNOWN_SO','PATH_HIJACK','SYMBOL_INTERPOSITION','MISSING_BASELINE')),
    process_key TEXT NOT NULL REFERENCES process_instances(process_key),
    pid INTEGER NOT NULL,
    exe TEXT NOT NULL,
    detail TEXT NOT NULL CHECK(json_valid(detail)),
    timestamp INTEGER NOT NULL,
    deduplication_key TEXT NOT NULL UNIQUE
);
```

Inspect a retained demo using canonical queries:

```bash
sqlite3 /tmp/ldwatch-demo-review/events.db \
  'SELECT id,process_key,pid,exe,event_type,subject_path,origin FROM loader_events ORDER BY id LIMIT 10;'
sqlite3 /tmp/ldwatch-demo-review/events.db \
  'SELECT rule,severity,COUNT(*) FROM alerts GROUP BY rule,severity;'
```

Exact table/index/constraint definitions are maintained in
[store migrations](internal/store/migrations) and [schema](internal/store/schema.sql).
See [persistence policy](docs/persistence.md) for atomic writes, busy/disk-full
behavior, retention, unknown timestamps and legacy migration handling.

---

## Alert Format

The CLI exports a top-level JSON array of persisted alerts. This illustrative
entry matches current field names and types; actual UUIDs, process keys and
timestamps vary per execution:

```json
[
  {
    "ID": "d2c76aed-84b5-4ec7-b58d-3511305934eb",
    "Severity": "HIGH",
    "Rule": "UNKNOWN_SO",
    "ProcessKey": "51995:156560",
    "Pid": 51995,
    "Exe": "/usr/bin/true",
    "Detail": "{\"baseline\":{\"value\":{\"approved_libraries\":[\"/usr/lib/libc.so.6\"]},\"version\":1},\"event_type\":\"LOAD\",\"executable\":\"/usr/bin/true\",\"flags\":0,\"observed\":{\"path\":\"/tmp/ldwatch-demo-review/libdeviation.so\"},\"origin\":\"unknown\",\"process_instance\":\"51995:156560\"}",
    "Timestamp": 1791266791630120987,
    "DeduplicationKey": "bbfae6f22bf7cf39cc5a1451767a7c627577f99a3e21ed4723956cd061f99fcf"
  }
]
```

Detail is a JSON-encoded string, not a nested report object. Its decoded
canonical keys are event_type, process_instance, executable, observed, baseline,
origin and flags. Timestamps are Unix nanoseconds; the alerts command renders
them as RFC3339Nano. Empty report output is [].

```bash
jq 'length' /tmp/ldwatch-demo-review/report.json
jq 'map(.Rule) | group_by(.) | map({rule: .[0], count: length})' \
  /tmp/ldwatch-demo-review/report.json
jq '.[] | select(.Rule == "UNKNOWN_SO") | .Detail | fromjson' \
  /tmp/ldwatch-demo-review/report.json
```

The [verified demo output](docs/collector_demo.md#verified-output) contains four
initial coverage alerts and one deviation. Reports support severity/date
filters without the former 10,000-row truncation. The CLI still buffers the
matching rows and formatted JSON in memory; it is not a bounded-memory streaming
export. Narrow the severity/date range for large databases. Regression tests
cover 10,050 alerts, historical ranges and inserts during an active read.

---

## Known Limitations

**Opt-in observation and asynchronous detection.**
Only explicitly instrumented Linux/glibc programs are covered. Alerts can arrive
after library code has run; monitoring does not prevent damage.

**Telemetry trust, integrity and loss.**
Compromised processes can omit or forge in-process telemetry. Peer credentials
identify connections, not record truth. Canonical paths do not verify file
contents. Bounded transport/object tracking, queue pressure, truncation and
storage failures can reduce coverage. Counters reset on restart; there is no
durable overflow spool or universal no-loss guarantee. See
[threat model](docs/threat-model.md) and [T09 measurements](docs/t09-evidence.md).
**Audit diagnostics are opt-in and bounded.**
Normal operation emits no hook logs. `LDWATCH_VERBOSE=1` writes best-effort
fragments only to an already nonblocking stderr pipe; other descriptor types
are skipped, full pipes drop fragments, and closed readers do not terminate the
application through audit logging. Telemetry delivery is independent of these
diagnostics. See [logging policy and regression evidence](docs/audit-logging.md).

**Statically linked binaries are not covered.**
`LD_AUDIT` only works when `ld.so` is involved. A statically linked binary
doesn't use the dynamic linker, so `audit.so` never loads and no telemetry
is produced. Coverage for static binaries requires eBPF `execve` tracing
and is documented as future work.

**Secure-execution instrumentation is outside supported coverage.**
The glibc loader restricts relevant environment variables in secure-execution
mode, including common setuid/setgid cases. A custom audit library is not
guaranteed to load in that mode. Root execution alone is not secure execution.
See `ld.so(8)` for exact restrictions; do not infer universal root/setuid
coverage or claim that all `LD_*` variables behave identically.

**Baseline variance for plugin-heavy binaries.**
Some binaries load optional SOs depending on runtime configuration (e.g., curl
with LDAP/NSS modules, Python with C extensions). The baseline profiler handles
this by distinguishing required SOs from optional ones, but tuning is needed
per environment. Required/optional absence is visible in CLI diff; the streaming
rules do not provide an end-of-process missing-library alert. Future work
includes static/system-wide sources, content integrity, privileged-preload
evidence and additional platforms/loaders/symbols.

---

## References

All six original paper citations, the threat classification and loader
references are retained below. Four publisher/author-hosted records were
verified for T11; the two IEEE pages blocked automated verification, so their
original title/year claims remain explicitly pending manual confirmation.
See [reference verification](docs/references.md). These sources provide
background, not proof of LD-Watch performance or implemented defenses.


### Papers

1. **Resolving the Correct Library: A Loader-Level Defense Solution Against Shared Object Hijacking (2026)**
   arXiv — https://arxiv.org/abs/2605.26665

2. **User-space Library Rootkits Revisited: Are User-space Detection Mechanisms Futile? (2025)**
   arXiv — https://arxiv.org/abs/2506.07827

3. **Malware Detection on Linux Using Runtime Opcode Tracing (2024)**
   IEEE — https://ieeexplore.ieee.org/document/10753555
   Original citation retained; metadata pending manual verification.

4. **Anomaly Based Malware Threat Detection on Linux Systems (2024)**
   IEEE — https://ieeexplore.ieee.org/document/10538975
   Original citation retained; metadata pending manual verification.

5. **Trace of the Times: Rootkit Detection through Temporal Anomalies in Kernel Activity (2025)**
   arXiv — https://arxiv.org/html/2503.02402

6. **Unmasking the Unseen: A Deep Dive into Modern Linux Rootkits and Detection Strategies (2025)**
   Virus Bulletin — https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Unmasking-the-unseen-a-deep-dive-into-modern-Linux-rootkits-and-their-detection.pdf

### Threat Classification

- **MITRE ATT&CK T1574.006 — Dynamic Linker Hijacking**
  https://attack.mitre.org/techniques/T1574/006

### Documentation

- Linux `rtld-audit(7)` man page — `man 7 rtld-audit`
- GNU C Library — Dynamic Linker Audit API
  https://www.gnu.org/software/libc/manual/html_node/Dynamic-Linker-Auditing.html

---

_LD-Watch — BE Computer Engineering Major Project_
