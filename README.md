# LD-Watch — Project Plan
### A Real-Time Threat Detection Engine for Dynamic Linker Exploitation on Linux

---

## Repository Structure

```
ld-watch/
├── audit/                  # C — LD_AUDIT shared library (core hook)
│   ├── src/
│   │   ├── audit.c
│   │   ├── ipc.c           # Unix socket sender
│   │   └── hooks.c         # la_objopen, la_symbind64, la_objsearch
│   ├── include/
│   │   └── audit.h
│   └── Makefile
│
├── collector/              # Go — daemon that receives telemetry
│   ├── main.go
│   ├── socket/
│   ├── store/              # SQLite writes
│   └── proto/              # shared message structs
│
├── engine/                 # Go — detection rules engine
│   ├── rules/
│   │   ├── unknown_so.go
│   │   ├── path_hijack.go
│   │   └── symbol_interpose.go
│   ├── baseline/
│   └── alerts/
│
├── cli/                    # Go — CLI tool (cobra)
│   └── cmd/
│       ├── alerts.go
│       ├── baseline.go
│       ├── watch.go
│       └── diff.go
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── attack-scenarios/   # controlled attack payloads for validation
│       ├── ld_preload_hook/
│       ├── path_hijack/
│       └── symbol_interpose/
│
├── scripts/
│   ├── setup.sh            # one-command dev environment setup
│   ├── baseline.sh         # run baselining for common binaries
│   └── run_tests.sh
│
├── docs/
│   ├── architecture.md
│   └── api.md
│
├── docker/
│   └── Dockerfile          # isolated test environment
│
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI
│
├── go.mod
├── go.sum
├── README.md
└── Makefile                # top-level build orchestration
```

---

## Team Split

| Member | Ownership |
|--------|-----------|
| Member 1 | `audit/` — C library, all LD_AUDIT hooks, IPC sender |
| Member 2 | `collector/` — Go daemon, SQLite schema, socket receiver |
| Member 3 | `engine/` — detection rules, baseline profiler, alert store |
| Member 4 | `cli/` + `tests/` + `attack-scenarios/` |

> Everyone reviews PRs outside their own area. No merging your own PR.

---

## Phase 1 — Project Setup (Week 1)

### 1.1 Repository Init
```bash
# One person does this, rest clone
git clone https://github.com/your-org/ld-watch.git
cd ld-watch
mkdir -p audit/src audit/include collector engine cli tests/unit \
         tests/integration tests/attack-scenarios scripts docs docker
```

### 1.2 Dependency Setup
```bash
# Run this once on any Ubuntu 22.04 / 24.04 machine
sudo apt update
sudo apt install -y gcc make libsqlite3-dev git curl

# Install Go 1.22+
curl -OL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Init Go module
cd ld-watch
go mod init github.com/your-org/ld-watch
```

### 1.3 Docker Environment (for safe testing)
```dockerfile
# docker/Dockerfile
FROM ubuntu:22.04
RUN apt update && apt install -y gcc make libsqlite3-dev curl git strace
RUN curl -OL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
WORKDIR /ld-watch
COPY . .
RUN make all
```

```bash
# Build and enter container
docker build -t ld-watch-dev ./docker
docker run -it --rm -v $(pwd):/ld-watch ld-watch-dev bash
```

### 1.4 Top-level Makefile
```makefile
all: audit collector cli

audit:
	$(MAKE) -C audit

collector:
	cd collector && go build -o ../bin/collector ./...

cli:
	cd cli && go build -o ../bin/ld-watch-cli ./...

test:
	bash scripts/run_tests.sh

clean:
	$(MAKE) -C audit clean
	rm -rf bin/
```

### 1.5 Git Workflow Rules
- `main` — always working, protected branch
- `dev` — integration branch, PRs go here first
- Feature branches: `feature/audit-hooks`, `feature/detection-rules`, etc.
- Commit format: `[component] short description` e.g. `[audit] add la_symbind64 hook`
- No force pushes. Squash before merging.

---

## Phase 2 — Audit Library (Week 2–3)

### Goal
Build `audit/audit.so` — the C shared library that hooks `ld.so`.

### Steps

**Step 1 — Minimal skeleton**
```c
// audit/src/audit.c
#include <link.h>
#include <stdio.h>

unsigned int la_version(unsigned int version) {
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    fprintf(stderr, "[ld-watch] loaded: %s\n", map->l_name);
    return LA_FLG_BINDFROM | LA_FLG_BINDTO;
}
```

```makefile
# audit/Makefile
CC = gcc
CFLAGS = -shared -fPIC -Wall -O2
audit.so: src/audit.c
    $(CC) $(CFLAGS) -o audit.so src/audit.c -ldl
```

**Step 2 — Smoke test the skeleton**
```bash
make -C audit
LD_AUDIT=./audit/audit.so ls /tmp
# Should print every .so loaded by ls
```

**Step 3 — Add all hooks**
Implement in `hooks.c`:
- `la_objopen` — log: SO path, PID, timestamp
- `la_objsearch` — log: search name + flags (LA_SER_LIBPATH = LD_LIBRARY_PATH used)
- `la_symbind64` — log: symbol name + resolved address + which SO it came from

**Step 4 — IPC sender**
Implement in `ipc.c` — connect to `/run/ld-watch.sock` and send a binary
struct per event. Keep it async-signal-safe: use `write()` directly, no malloc,
no printf in the hot path.

```c
typedef struct {
    uint32_t pid;
    uint8_t  event_type;   // 0=so_load, 1=sym_bind, 2=so_search
    char     so_path[256];
    char     symbol[128];
    uint64_t resolved_addr;
    uint8_t  mechanism;    // 0=standard, 1=LD_PRELOAD, 2=LD_LIBRARY_PATH
    uint64_t timestamp_ns;
} sl_event_t;
```

---

## Phase 3 — Collector Daemon (Week 4–5)

### Goal
Go daemon that receives events from `audit.so` and persists them to SQLite.

### Steps

**Step 1 — Socket listener**
```go
// collector/socket/listener.go
ln, err := net.Listen("unix", "/run/ld-watch.sock")
// accept connections, read sl_event_t structs in a loop
```

**Step 2 — SQLite schema**
```sql
CREATE TABLE so_events (
    id            INTEGER PRIMARY KEY,
    pid           INTEGER,
    exe           TEXT,
    so_path       TEXT,
    mechanism     TEXT,  -- standard | LD_PRELOAD | LD_LIBRARY_PATH
    timestamp     INTEGER
);

CREATE TABLE symbol_events (
    id            INTEGER PRIMARY KEY,
    pid           INTEGER,
    exe           TEXT,
    symbol_name   TEXT,
    resolved_so   TEXT,
    resolved_addr INTEGER,
    timestamp     INTEGER
);

CREATE TABLE processes (
    pid           INTEGER PRIMARY KEY,
    exe           TEXT,
    cmdline       TEXT,
    first_seen    INTEGER
);

CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    severity      TEXT,
    rule          TEXT,
    pid           INTEGER,
    exe           TEXT,
    detail        TEXT,  -- JSON
    timestamp     INTEGER
);
```

**Step 3 — Wire them together**
Collector receives event → writes to `so_events` or `symbol_events` → passes
to Detection Engine → if rule fires, writes to `alerts`.

---

## Phase 4 — Detection Engine (Week 6–7)

### Goal
Three detection rules that cover the three project objectives.

### Steps

**Step 1 — Baseline profiler**
Run in learn mode: collect SO loads for 20+ common binaries over 5 runs each.
Store expected SO set per binary in `baseline` table.

```bash
# scripts/baseline.sh
BINARIES=("/bin/ls" "/bin/curl" "/usr/bin/ssh" "/usr/bin/sudo" \
          "/bin/bash" "/usr/bin/python3" "/usr/bin/wget")

for bin in "${BINARIES[@]}"; do
    for i in {1..5}; do
        LD_AUDIT=./audit/audit.so $bin --version 2>/dev/null
    done
done
```

**Step 2 — Rule 1: Unknown SO**
```go
// engine/rules/unknown_so.go
// If so_path not in baseline expected_sos for this exe → ALERT HIGH
```

**Step 3 — Rule 2: Path Hijack**
```go
// engine/rules/path_hijack.go
// SO name matches baseline but path is different → ALERT CRITICAL
// e.g. libssl.so.3 loading from /tmp/ instead of /lib/x86_64-linux-gnu/
```

**Step 4 — Rule 3: Symbol Interposition**
```go
// engine/rules/symbol_interpose.go
// resolved_so != expected_so for critical symbol → ALERT CRITICAL
// Critical symbols: execve, connect, open, getpwuid, read, write
```

**Step 5 — Bonus Rule: LD_PRELOAD on privileged binary**
```go
// mechanism == LD_PRELOAD AND (process is root OR setuid binary) → CRITICAL
```

---

## Phase 5 — CLI (Week 8)

### Commands
```bash
ld-watch-cli alerts                    # show recent alerts
ld-watch-cli alerts --severity CRITICAL
ld-watch-cli baseline --exe /bin/curl  # show baseline for a binary
ld-watch-cli watch --pid 1234          # live events for a PID
ld-watch-cli diff /usr/bin/ssh         # current load map vs baseline
ld-watch-cli report --output report.json
```

---

## Phase 6 — Testing

### 6.1 Unit Tests

**Audit library (C) — test each hook in isolation**
```bash
# tests/unit/test_hooks.sh
# Load a known binary under LD_AUDIT and assert expected output

LD_AUDIT=./audit/audit.so ls / 2>&1 | grep -q "libc.so" && echo PASS || echo FAIL
LD_AUDIT=./audit/audit.so ls / 2>&1 | grep -q "libdl.so" && echo PASS || echo FAIL
```

**Collector (Go) — test SQLite writes**
```go
// tests/unit/collector_test.go
func TestSOEventWrite(t *testing.T) {
    db := setupTestDB(t)
    event := SOEvent{PID: 1234, SOPath: "/lib/libc.so.6", Mechanism: "standard"}
    err := WriteSOEvent(db, event)
    assert.NoError(t, err)
    // query back and assert fields match
}
```

**Detection Engine (Go) — test each rule**
```go
// tests/unit/rules_test.go

func TestUnknownSORule(t *testing.T) {
    baseline := []string{"/lib/libc.so.6", "/lib/libssl.so.3"}
    event := SOEvent{Exe: "/bin/curl", SOPath: "/tmp/evil.so"}
    alert := RunUnknownSORule(baseline, event)
    assert.Equal(t, "HIGH", alert.Severity)
}

func TestPathHijackRule(t *testing.T) {
    event := SOEvent{
        Exe:    "/bin/curl",
        SOPath: "/tmp/evil/libssl.so.3",  // wrong path
    }
    alert := RunPathHijackRule(event)
    assert.Equal(t, "CRITICAL", alert.Severity)
}

func TestSymbolInterpositionRule(t *testing.T) {
    event := SymbolEvent{
        Symbol:     "connect",
        ResolvedSO: "/tmp/libhook.so",  // not libc
        ExpectedSO: "/lib/libc.so.6",
    }
    alert := RunSymbolInterpositionRule(event)
    assert.Equal(t, "CRITICAL", alert.Severity)
}
```

**Run all Go tests:**
```bash
go test ./... -v
```

---

### 6.2 Integration Tests

**Test 1 — Full pipeline with a clean binary**
```bash
# Start collector daemon
./bin/collector &

# Run ls under audit
LD_AUDIT=./audit/audit.so ls /tmp

# Assert: so_events table has entries, no alerts generated
sqlite3 /var/ld-watch/events.db "SELECT count(*) FROM so_events WHERE exe LIKE '%ls%';"
sqlite3 /var/ld-watch/events.db "SELECT count(*) FROM alerts;" # should be 0
```

**Test 2 — LD_LIBRARY_PATH hijack detected**
```bash
mkdir -p /tmp/fakelibs
cp /lib/x86_64-linux-gnu/libz.so.1 /tmp/fakelibs/

LD_LIBRARY_PATH=/tmp/fakelibs LD_AUDIT=./audit/audit.so python3 -c "import zlib"

# Assert: alert generated with rule=PATH_HIJACK
sqlite3 /var/ld-watch/events.db "SELECT * FROM alerts WHERE rule='PATH_HIJACK';"
```

**Test 3 — LD_PRELOAD injection detected**
```bash
# Write a minimal evil.so that exports malloc
echo '#include <stdlib.h>
void* malloc(size_t s){ return NULL; }' > /tmp/evil.c
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c

LD_PRELOAD=/tmp/evil.so LD_AUDIT=./audit/audit.so ls

# Assert: alert generated with rule=UNKNOWN_SO or LD_PRELOAD_PRIVILEGED
sqlite3 /var/ld-watch/events.db "SELECT * FROM alerts;"
```

---

### 6.3 Attack Scenario Validation

These are controlled attack payloads in `tests/attack-scenarios/` to simulate real threats and confirm detection.

**Scenario 1 — LD_PRELOAD Rootkit**
```c
// tests/attack-scenarios/ld_preload_hook/evil.c
// Hooks read() to filter output — classic rootkit technique
#define _GNU_SOURCE
#include <dlfcn.h>
typedef ssize_t (*orig_read_t)(int, void*, size_t);
ssize_t read(int fd, void *buf, size_t count) {
    orig_read_t orig = dlsym(RTLD_NEXT, "read");
    return orig(fd, buf, count);
}
```
```bash
gcc -shared -fPIC -o evil.so evil.c -ldl
LD_PRELOAD=./evil.so LD_AUDIT=../../../audit/audit.so ls
# Expected alert: UNKNOWN_SO + SYMBOL_INTERPOSITION on read()
```

**Scenario 2 — LD_LIBRARY_PATH Path Hijack**
```bash
# tests/attack-scenarios/path_hijack/run.sh
mkdir -p /tmp/hijack
cp /lib/x86_64-linux-gnu/libcurl.so.4 /tmp/hijack/
# Simulate: malicious libcurl in /tmp replaces real one
LD_LIBRARY_PATH=/tmp/hijack LD_AUDIT=../../../audit/audit.so curl --version
# Expected alert: PATH_HIJACK for libcurl.so.4
```

**Scenario 3 — Symbol Interposition (Credential Stealer sim)**
```c
// tests/attack-scenarios/symbol_interpose/stealer.c
// Hooks getpwuid to intercept credential lookups
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pwd.h>
struct passwd* getpwuid(uid_t uid) {
    // log uid to /tmp/stolen.log
    FILE* f = fopen("/tmp/stolen.log", "a");
    fprintf(f, "getpwuid called for uid %d\n", uid);
    fclose(f);
    typedef struct passwd* (*orig_t)(uid_t);
    orig_t orig = dlsym(RTLD_NEXT, "getpwuid");
    return orig(uid);
}
```
```bash
gcc -shared -fPIC -o stealer.so stealer.c -ldl
LD_PRELOAD=./stealer.so LD_AUDIT=../../../audit/audit.so id
# Expected alert: SYMBOL_INTERPOSITION on getpwuid — CRITICAL
```

---

### 6.4 Run All Tests Script
```bash
# scripts/run_tests.sh
#!/bin/bash
set -e
echo "=== Unit Tests ==="
go test ./... -v

echo "=== Integration Tests ==="
bash tests/integration/test_clean_binary.sh
bash tests/integration/test_path_hijack.sh
bash tests/integration/test_ld_preload.sh

echo "=== Attack Scenarios ==="
bash tests/attack-scenarios/ld_preload_hook/run.sh
bash tests/attack-scenarios/path_hijack/run.sh
bash tests/attack-scenarios/symbol_interpose/run.sh

echo "=== All tests passed ==="
```

---

## Phase 7 — CI/CD (Week 9)

```yaml
# .github/workflows/ci.yml
name: LD-Watch CI

on: [push, pull_request]

jobs:
  build-and-test:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3

      - name: Install system deps
        run: sudo apt-get install -y gcc make libsqlite3-dev

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Build audit library
        run: make -C audit

      - name: Build Go components
        run: go build ./...

      - name: Run unit tests
        run: go test ./... -v

      - name: Run integration tests
        run: bash scripts/run_tests.sh
```

---

## Phase Timeline Summary

| Phase | What | Who | Weeks |
|-------|------|-----|-------|
| 1 | Project setup, repo, Docker, Makefile | All together | 1 |
| 2 | Audit C library + IPC | Member 1 | 2–3 |
| 3 | Collector daemon + SQLite | Member 2 | 4–5 |
| 4 | Detection engine + baseline | Member 3 | 6–7 |
| 5 | CLI tool | Member 4 | 8 |
| 6 | Unit + integration + attack scenario tests | Member 4 + all | 9–10 |
| 7 | CI, cleanup, demo prep | All | 11–12 |

---

## Quick Start (for any team member)

```bash
git clone https://github.com/your-org/ld-watch.git
cd ld-watch
bash scripts/setup.sh       # installs all deps
make all                    # builds everything
make test                   # runs all tests
```
