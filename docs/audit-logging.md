# Bounded audit diagnostics (#64)

Normal audit operation is silent. Unset LDWATCH_VERBOSE, `0`, and values other
than exactly `1` disable diagnostic output. Socket telemetry remains independent
of this setting and continues to use the configured collector endpoint.

`LDWATCH_VERBOSE=1` opts into best-effort diagnostics **only when stderr is an
already nonblocking pipe** (FIFO with O_NONBLOCK). Blocking pipes, terminals,
regular files, sockets and invalid descriptors receive no audit diagnostic
writes. The caller owns the pipe configuration and must keep it nonblocking;
the audit library never changes the application's descriptor flags.

Each fragment is capped at 4096 bytes (Linux PIPE_BUF) and gets one write
attempt. Full pipes drop fragments; there is no retry or capacity wait. Output
can be incomplete or interleaved and is not a reliable telemetry source.
Broken-pipe SIGPIPE from that write is blocked in the current thread and consumed
when newly generated, without changing the process signal disposition or
consuming a previously pending SIGPIPE. The previous signal mask and errno are
restored after the diagnostic attempt.

This intentionally changes old behavior: setting LDWATCH_VERBOSE=1 with normal
terminal/file redirection does not print hook logs. Use collector/CLI queries
for routine observation. The C fixture adapter configures and drains a pipe for
diagnostic hook tests; it is not a production logger:

```bash
gcc -Wall -Wextra -O2 -o /tmp/ldwatch-log-fixture tests/fixtures/audit_logging.c
LDWATCH_VERBOSE=1 /tmp/ldwatch-log-fixture capture "$PWD/audit/audit.so" /bin/true
```

## Regression evidence

Before the fix, the adapter with a prefilled blocking stderr pipe and default
logging timed out (exit 124). No pipe reader consumed data.

`scripts/test_audit.sh` now verifies default silence and completion with a full
blocking pipe, opt-in completion with full nonblocking/blocking pipes and a
closed reader, unchanged stderr descriptor flags, and visible hook/formatter
output through a draining nonblocking pipe. The remaining socket/real-source
fixtures continue to run in the same required suite.
