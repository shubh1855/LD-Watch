# T09 integration and performance evidence

Validation recorded 2026-10-05 on `feature/t09`.

## Functional checks

- `go test -race ./...` passed, including real C audit-library traffic through
  the Go `SOCK_SEQPACKET` listener, process identity persistence, invalid packet
  rejection, and threaded plugin load/unload/reload attribution.
- `go vet ./...` passed.
- `bash scripts/test_audit.sh` passed 15/15 checks. The script now checks that
  an audited process exits with an absent collector, completes while a connected
  receiver does not read, and reconnects to a restarted endpoint in the same
  process. It also verifies a C record reaches the controlled receiver.
- Existing store checks cover migration history, legacy preservation, migration
  rollback, event-write failure, SQLite busy/disk-full behavior, and restart
  persistence.

## Workload measurements

Environment: WSL2 Ubuntu 26.04, Go 1.26.1, Linux amd64, 12th Gen Intel Core
i5-12450H. The collector benchmarks use four workers and the project's
`modernc.org/sqlite` in-memory database. The checkout resides on the WSL-mounted
Windows filesystem, so these timings include that environment's I/O overhead.

| Workload | Result |
| --- | --- |
| 1,000 synthetic 1,024-byte packets through encode/send/decode/process/SQLite | 8,488 events/s, 8.69 MB/s; all 1,000 rows persisted |
| 30-second packet-ingestion benchmark | 291,062 rows, 7,534 events/s, 7.72 MB/s; the benchmark verified row count equals packet count |
| 1,000 `/bin/true` starts without `LD_AUDIT` | 420.9 µs/op |
| 1,000 `/bin/true` starts with `LD_AUDIT` and no collector | 656.8 µs/op, about 56% above the unaudited run |

The packet benchmark includes a final exact row-count check. It measures this
synthetic collector workload, not arbitrary C callback patterns or a production
loss rate. The short-process comparison includes process startup and the bounded
failed socket connection; it is not a general application-overhead estimate.
The slow-receiver fixture verifies bounded application completion but does not
measure the number of C-side drops. No universal no-loss claim is made.

## Remaining T09 gate

CLI report workflows belong to T08, which is still incomplete in the checklist.
The existing T07 clean/deviation fixture verifies stored alerts, but T09 cannot
verify those outcomes through CLI reports until T08 supplies that interface.
Accordingly, these results cover T09's collector, protocol, lifecycle,
failure-handling, migration, and workload-measurement checks; the overall T09
gate remains open for the T08-dependent CLI report coverage.
