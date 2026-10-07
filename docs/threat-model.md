# Threat model and coverage limits

## Supported observation

LD-Watch targets explicitly instrumented x86_64 Linux/glibc dynamically linked
processes. It detects deviations from operator-approved path/provider profiles.
It does not inspect malicious library semantics or prevent library execution.
Asynchronous alerts may arrive after code has run.

Loader callbacks distinguish candidates, loads, bindings and closes. Symbol
coverage is the configured critical set in `audit/include/audit.h`, not every
function call. A symbol with no approved provider expectation cannot establish
a provider deviation. Absence of a required library is visible in CLI diff;
do not claim an end-of-process missing-library alert from the streaming rules.

## Trust boundaries

- Trust the OS/loader, collector executable, database permissions and approval
  operator for this deployment model.
- An audited process can be adversarial. In-process telemetry can be forged,
  omitted or disrupted. SO_PEERCRED identifies socket peers, not event truth.
- Baselines learned from compromised workloads can authorize malicious paths.
  Review candidate observations and keep the explicit environment label stable.
- Canonical paths are identity hints, not content hashes/signatures. Replacing
  library contents at the same path is outside the integrity guarantee.
- A privileged host attacker can alter the collector/database/runtime; this
  project does not provide a tamper-proof host security boundary.

## Coverage gaps

Static binaries, other loaders/platforms, uninstrumented programs and universal
system-wide monitoring are outside scope. Secure-execution mode restricts loader
environment instrumentation; a normal custom audit library is not guaranteed
to load for setuid/setgid/capability-sensitive execution. Do not equate running
as root with secure execution. See [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html).

The source cannot prove preload origin or effective privilege context, so
PRELOAD_PRIVILEGED is deferred. An LD_PRELOAD deviation may still generate
UNKNOWN_SO or a provider alert without attribution to the injection mechanism.

Bounded transport protects application progress but can drop events. Queue,
object-capacity, truncation, unresolved identity and storage failures reduce
coverage. Counters and persisted uncertainty make some degradation visible;
they do not establish a universal no-loss rate. There is no durable overflow
spool and counters reset on restart. SQLite retention is explicit and disabled
by default; operator disk capacity remains necessary.

## Evidence and future work

The [isolated demo](collector_demo.md) verifies baseline/clean/deviation/report
behavior. [T09 evidence](t09-evidence.md) distinguishes actual source fixtures,
synthetic collector benchmarks and environment-specific overhead measurements.
Those results are not broad production certification.

Deferred: privileged-preload evidence, static/system-wide sources, file-content
integrity, additional architectures/loaders/symbols and durable loss recovery.
These require separate designs and tests, not documentation checkmarks.
