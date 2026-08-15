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
interface, intercepts every shared object load event in real time, compares
it against a known-good baseline, and raises an alert the moment something
unexpected appears — wrong file, wrong location, wrong symbol resolution.

---

## Problem Statement

Modern operating systems silently load shared components every time a program
runs — a process that happens in milliseconds and goes largely unmonitored.
Attackers exploit this blind spot to inject malicious code into legitimate
programs, hijack trusted system tools, and steal credentials without triggering
traditional security tools. Current solutions focus on files, network traffic,
and system calls — but nothing watches the loader itself. This project builds
a real-time detection engine that sits inside the loading mechanism, tracks
exactly what gets loaded and from where, and raises an alert the moment
something unexpected appears.

---

## Objectives

**1. Dynamic Linker Telemetry**
Monitor every program on the system and track exactly which supporting files
and components it loads when it starts, so we always have a clear picture of
what is running and where it came from.

**2. Baseline Deviation Detection**
Build a "what normal looks like" reference for common system programs, and
automatically raise an alert when something unexpected gets loaded — like a
known program suddenly pulling in a suspicious file from an unusual location.

**3. Symbol Interposition Detection**
Detect when a malicious component silently intercepts critical system functions
— the technique attackers use to steal credentials, hide processes, or tamper
with system behavior — before any damage is done.

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
│                  └── la_symbind64()   symbol resolved        │
└──────────────────────────┬───────────────────────────────────┘
                           │ Unix socket (/run/ldwatch.sock)
                           │ binary struct per event
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
             │  so_events              │
             │  symbol_events          │
             │  alerts                 │
             └────────────┬────────────┘
                          │
             ┌────────────▼────────────┐
             │     ldwatch-cli         │  (Go + cobra)
             │  alerts / watch / diff  │
             └─────────────────────────┘
```

### IPC Protocol

The audit library and collector daemon communicate over a Unix domain socket
using a fixed-size binary struct. No JSON in the hot path — raw binary write
for minimum overhead inside the audited process.

```c
typedef struct {
    uint32_t pid;
    uint8_t  event_type;     // 0=so_load, 1=sym_bind, 2=so_search
    char     so_path[256];
    char     symbol[128];
    uint64_t resolved_addr;
    uint8_t  mechanism;      // 0=standard, 1=LD_PRELOAD, 2=LD_LIBRARY_PATH
    uint64_t timestamp_ns;
} ldwatch_event_t;
```

### Detection Rules

| Rule                 | Trigger                                      | Severity |
| -------------------- | -------------------------------------------- | -------- |
| UNKNOWN_SO           | SO not in baseline for this binary           | HIGH     |
| PATH_HIJACK          | SO name matches baseline but path differs    | CRITICAL |
| SYMBOL_INTERPOSITION | Critical symbol resolves outside expected SO | CRITICAL |
| PRELOAD_PRIVILEGED   | LD_PRELOAD used on root/setuid binary        | CRITICAL |

---

## Tech Stack

| Component    | Language       | Why                                                   |
| ------------ | -------------- | ----------------------------------------------------- |
| `audit/`     | C              | LD_AUDIT is a C interface — mandatory                 |
| `collector/` | Go             | Goroutines make concurrent socket+DB trivial          |
| `engine/`    | Go             | Clean rule composition, easy to extend                |
| `cli/`       | Go + cobra     | Single binary, great flag/subcommand support          |
| Storage      | SQLite         | No server dependency, portable, fast enough           |
| Container    | Docker         | Isolated safe environment for attack scenario testing |
| CI           | GitHub Actions | Automated build + test on every push                  |

> **Note on C/Go boundary:** There is no CGo anywhere in this project.
> The C audit library and Go daemon are separate processes that communicate
> over a Unix socket. The boundary is pure IPC — not language interop.

---

## Repository Structure

```
ld-watch/
├── audit/                        # C — LD_AUDIT shared library
│   ├── src/
│   │   ├── audit.c               # entry point, la_version
│   │   ├── hooks.c               # la_objopen, la_objsearch, la_symbind64
│   │   └── ipc.c                 # Unix socket sender
│   ├── include/
│   │   └── audit.h               # shared struct definitions
│   └── Makefile
│
├── collector/                    # Go — telemetry collection daemon
│   ├── main.go
│   ├── socket/
│   │   └── listener.go           # Unix socket receiver
│   ├── store/
│   │   └── sqlite.go             # SQLite writes
│   └── proto/
│       └── event.go              # Go mirror of ldwatch_event_t
│
├── engine/                       # Go — detection rules engine
│   ├── rules/
│   │   ├── unknown_so.go
│   │   ├── path_hijack.go
│   │   └── symbol_interpose.go
│   ├── baseline/
│   │   └── profiler.go           # learn mode + baseline storage
│   └── alerts/
│       └── store.go              # alert generation + persistence
│
├── cli/                          # Go — CLI tool
│   └── cmd/
│       ├── root.go
│       ├── alerts.go             # ldwatch-cli alerts
│       ├── baseline.go           # ldwatch-cli baseline
│       ├── watch.go              # ldwatch-cli watch
│       ├── diff.go               # ldwatch-cli diff
│       └── report.go             # ldwatch-cli report
│
├── tests/
│   ├── unit/
│   │   ├── test_hooks.sh         # C hook smoke tests
│   │   ├── collector_test.go     # SQLite write tests
│   │   └── rules_test.go         # detection rule unit tests
│   ├── integration/
│   │   ├── test_clean_binary.sh  # full pipeline, clean binary
│   │   ├── test_path_hijack.sh   # LD_LIBRARY_PATH detection
│   │   └── test_ld_preload.sh    # LD_PRELOAD detection
│   └── attack-scenarios/         # controlled attack payloads
│       ├── ld_preload_hook/
│       │   ├── evil.c
│       │   └── run.sh
│       ├── path_hijack/
│       │   └── run.sh
│       └── symbol_interpose/
│           ├── stealer.c
│           └── run.sh
│
├── scripts/
│   ├── setup.sh                  # one-command dev environment setup
│   ├── baseline.sh               # baseline profiling for common binaries
│   └── run_tests.sh              # runs all test layers
│
├── docs/
│   ├── architecture.md           # detailed architecture notes
│   ├── api.md                    # IPC protocol and struct spec
│   └── threat-model.md           # attack scenarios and coverage
│
├── docker/
│   └── Dockerfile                # isolated Ubuntu 22.04 test environment
│
├── .github/
│   └── workflows/
│       └── ci.yml                # GitHub Actions CI pipeline
│
├── go.mod
├── go.sum
├── Makefile                      # top-level build orchestration
└── README.md
```

---

## Team

| Member   | Component         | Responsibilities                                |
| -------- | ----------------- | ----------------------------------------------- |
| Member 1 | `audit/`          | C library, all LD_AUDIT hooks, IPC sender       |
| Member 2 | `collector/`      | Go daemon, SQLite schema, socket receiver       |
| Member 3 | `engine/`         | Detection rules, baseline profiler, alert store |
| Member 4 | `cli/` + `tests/` | CLI tool, all test layers, attack scenarios     |

> Everyone reviews PRs outside their own area. No merging your own PR.

---

## Git Workflow

### Branches

- `main` — always working and passing CI. Protected. No direct pushes.
- `dev` — integration branch. All PRs target here first.
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

**Phase 1 — Setup**

- [x] Repo created, all members have access
- [x] Branch protection rules set on `main`
- [x] `docker/Dockerfile` builds successfully
- [x] Top-level `Makefile` targets defined: `all`, `audit`, `collector`, `cli`, `test`, `clean`
- [x] `go.mod` initialized
- [x] `scripts/setup.sh` installs all deps on fresh Ubuntu 22.04
- [x] GitHub Actions CI skeleton runs on push

**Phase 2 — Audit Library**

- [x] `la_version()` returns `LAV_CURRENT`
- [x] `la_objopen()` fires and logs SO path + PID
- [x] `la_objsearch()` captures `LA_SER_LIBPATH` flag (LD_LIBRARY_PATH used)
- [x] `la_symbind64()` captures symbol name + resolved address
- [x] IPC sender writes `ldwatch_event_t` to Unix socket
- [x] Smoke test: `LD_AUDIT=./audit/audit.so ls` prints expected SOs

**Phase 3 — Collector Daemon**

- [ ] Listens on `/run/ldwatch.sock`
- [ ] Reads `ldwatch_event_t` structs correctly (field alignment verified)
- [ ] Writes `so_events` to SQLite
- [ ] Writes `symbol_events` to SQLite
- [ ] Passes events to detection engine
- [ ] Handles multiple concurrent processes without dropping events

**Phase 4 — Detection Engine**

- [ ] Baseline profiler runs in learn mode and stores expected SO sets
- [ ] Rule 1: UNKNOWN_SO fires correctly
- [ ] Rule 2: PATH_HIJACK fires correctly
- [ ] Rule 3: SYMBOL_INTERPOSITION fires correctly
- [ ] Bonus rule: PRELOAD_PRIVILEGED fires on LD_PRELOAD + root process
- [ ] Alerts written to `alerts` table with correct severity and JSON detail

**Phase 5 — CLI**

- [ ] `ldwatch-cli alerts` lists recent alerts
- [ ] `ldwatch-cli alerts --severity CRITICAL` filters correctly
- [ ] `ldwatch-cli baseline --exe /bin/curl` shows expected SO set
- [ ] `ldwatch-cli watch --pid <pid>` streams live events
- [ ] `ldwatch-cli diff /usr/bin/ssh` compares current vs baseline
- [ ] `ldwatch-cli report --output report.json` exports alert report

**Phase 6 — Testing**

- [ ] All unit tests pass: `go test ./... -v`
- [ ] Integration test 1 (clean binary) passes
- [ ] Integration test 2 (path hijack) passes
- [ ] Integration test 3 (LD_PRELOAD) passes
- [ ] Attack scenario 1 (LD_PRELOAD rootkit) detected
- [ ] Attack scenario 2 (path hijack) detected
- [ ] Attack scenario 3 (symbol interposition) detected

**Phase 7 — CI + Demo**

- [ ] Full CI pipeline passes on every push
- [ ] Docker demo environment runs all three attack scenarios end to end
- [ ] Report output generated cleanly for viva demo

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-org/ld-watch.git
cd ld-watch

# Install all dependencies (Ubuntu 22.04 / 24.04)
bash scripts/setup.sh

# Build everything
make all

# Run all tests
make test
```

---

## Building

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

# Enter the container with the repo mounted
docker run -it --rm -v $(pwd):/ld-watch ld-watch-dev bash

# Inside the container
make all
make test
```

---

## Running

### Step 1 — Start the collector daemon

```bash
sudo ./bin/collector --db /var/ldwatch/events.db --socket /run/ldwatch.sock
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
# Profile common system binaries (run once on a clean system)
bash scripts/baseline.sh
```

---

## Testing

### Unit Tests

**Audit C library hook smoke tests**

```bash
bash tests/unit/test_hooks.sh
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

- `TestSOEventWrite` — SQLite write and readback
- `TestUnknownSORule` — unknown SO triggers HIGH alert
- `TestPathHijackRule` — wrong path triggers CRITICAL alert
- `TestSymbolInterpositionRule` — wrong resolved SO triggers CRITICAL alert

### Integration Tests

**Test 1 — Clean binary, no alerts expected**

```bash
bash tests/integration/test_clean_binary.sh
```

Runs `ls` under LD-Watch, verifies `so_events` populated, verifies `alerts`
count is zero.

**Test 2 — LD_LIBRARY_PATH path hijack**

```bash
bash tests/integration/test_path_hijack.sh
```

Copies a real library to `/tmp/fakelibs/`, sets `LD_LIBRARY_PATH`, runs a
binary, verifies a `PATH_HIJACK` alert is generated.

**Test 3 — LD_PRELOAD injection**

```bash
bash tests/integration/test_ld_preload.sh
```

Compiles a minimal shared object, injects it via `LD_PRELOAD`, verifies
`UNKNOWN_SO` alert is generated.

### Run all test layers

```bash
make test
# or
bash scripts/run_tests.sh
```

---

## Attack Scenario Validation

These are controlled simulations of real attack techniques. Run them inside
the Docker container — do not run on a production machine.

### Scenario 1 — LD_PRELOAD Rootkit

Simulates a rootkit that hooks `read()` to filter process output — the exact
technique used by real Linux rootkits to hide files and processes.

```bash
cd tests/attack-scenarios/ld_preload_hook
gcc -shared -fPIC -o evil.so evil.c -ldl
LD_PRELOAD=./evil.so LD_AUDIT=../../../audit/audit.so ls
```

**Expected alerts:** `UNKNOWN_SO` (HIGH) + `SYMBOL_INTERPOSITION` on `read()` (CRITICAL)

---

### Scenario 2 — LD_LIBRARY_PATH Path Hijack

Simulates an attacker placing a malicious copy of a trusted library in `/tmp/`
and pointing `LD_LIBRARY_PATH` there so the process loads the fake one.

```bash
cd tests/attack-scenarios/path_hijack
bash run.sh
```

**Expected alert:** `PATH_HIJACK` for the shadowed library (CRITICAL)

---

### Scenario 3 — Symbol Interposition (Credential Stealer)

Simulates a credential stealer that hooks `getpwuid()` to intercept every
credential lookup and log it — the mechanism used by real password-stealing
malware on Linux.

```bash
cd tests/attack-scenarios/symbol_interpose
gcc -shared -fPIC -o stealer.so stealer.c -ldl
LD_PRELOAD=./stealer.so LD_AUDIT=../../../audit/audit.so id
cat /tmp/stolen.log   # shows intercepted uid lookups
```

**Expected alert:** `SYMBOL_INTERPOSITION` on `getpwuid` (CRITICAL)

---

## CLI Reference

```bash
# Show all recent alerts
ldwatch-cli alerts

# Filter by severity
ldwatch-cli alerts --severity CRITICAL
ldwatch-cli alerts --severity HIGH

# Show baseline for a binary
ldwatch-cli baseline --exe /bin/curl
ldwatch-cli baseline --exe /usr/bin/sudo

# Stream live events for a process
ldwatch-cli watch --pid 1234

# Compare current SO load map vs baseline
ldwatch-cli diff /usr/bin/ssh
ldwatch-cli diff /bin/curl

# Export alert report
ldwatch-cli report --output report.json
ldwatch-cli report --output report.json --since 2025-01-01
```

---

## Database Schema

```sql
-- Every shared object load event
CREATE TABLE so_events (
    id            INTEGER PRIMARY KEY,
    pid           INTEGER NOT NULL,
    exe           TEXT NOT NULL,
    so_path       TEXT NOT NULL,
    mechanism     TEXT NOT NULL,  -- standard | LD_PRELOAD | LD_LIBRARY_PATH
    timestamp     INTEGER NOT NULL
);

-- Every critical symbol resolution event
CREATE TABLE symbol_events (
    id            INTEGER PRIMARY KEY,
    pid           INTEGER NOT NULL,
    exe           TEXT NOT NULL,
    symbol_name   TEXT NOT NULL,
    resolved_so   TEXT NOT NULL,
    resolved_addr INTEGER NOT NULL,
    timestamp     INTEGER NOT NULL
);

-- Process registry
CREATE TABLE processes (
    pid           INTEGER PRIMARY KEY,
    exe           TEXT NOT NULL,
    cmdline       TEXT,
    first_seen    INTEGER NOT NULL
);

-- Known-good SO sets per binary
CREATE TABLE baseline (
    exe           TEXT NOT NULL,
    so_name       TEXT NOT NULL,
    expected_path TEXT NOT NULL,
    PRIMARY KEY (exe, so_name)
);

-- Generated alerts
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    severity      TEXT NOT NULL,   -- HIGH | CRITICAL
    rule          TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    exe           TEXT NOT NULL,
    detail        TEXT NOT NULL,   -- JSON
    timestamp     INTEGER NOT NULL
);
```

---

## Alert Format

```json
{
  "alert_id": "a1b2c3d4-...",
  "severity": "CRITICAL",
  "rule": "SYMBOL_INTERPOSITION",
  "pid": 1234,
  "exe": "/usr/bin/sudo",
  "detail": {
    "symbol": "getpwuid",
    "expected_so": "/lib/x86_64-linux-gnu/libc.so.6",
    "actual_so": "/tmp/.lib/libnss_evil.so",
    "resolved_addr": "0x7f3a2b1c0d00"
  },
  "timestamp": "2026-07-21T14:32:00Z"
}
```

---

## Known Limitations

**Statically linked binaries are not covered.**
`LD_AUDIT` only works when `ld.so` is involved. A statically linked binary
doesn't use the dynamic linker, so `audit.so` never loads and no telemetry
is produced. Coverage for static binaries requires eBPF `execve` tracing
and is documented as future work.

**Setuid binaries ignore LD_AUDIT.**
The Linux kernel strips all `LD_*` environment variables before executing a
setuid binary. This means `sudo`, `su`, and similar binaries cannot be audited
via this mechanism. This is actually a useful security finding — it also means
attackers cannot use LD_PRELOAD on these binaries either.

**Baseline variance for plugin-heavy binaries.**
Some binaries load optional SOs depending on runtime configuration (e.g., curl
with LDAP/NSS modules, Python with C extensions). The baseline profiler handles
this by distinguishing required SOs from optional ones, but tuning is needed
per environment.

---

## References

### Papers

1. **Resolving the Correct Library: Loader-Level Defense Against SO Hijacking (2026)**
   arXiv — https://arxiv.org/abs/2605.26665

2. **User-space Library Rootkits Revisited: Are User-space Detection Mechanisms Futile? (2025)**
   arXiv — https://arxiv.org/abs/2506.07827

3. **Malware Detection on Linux Using Runtime Opcode Tracing (2024)**
   IEEE — https://ieeexplore.ieee.org/document/10753555

4. **Anomaly Based Malware Threat Detection on Linux Systems (2024)**
   IEEE — https://ieeexplore.ieee.org/document/10538975

5. **Trace of the Times: Rootkit Detection through Temporal Anomalies (2025)**
   arXiv — https://arxiv.org/html/2503.02402

6. **Unmasking the Unseen: Modern Linux Rootkits and Detection (2025)**
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
