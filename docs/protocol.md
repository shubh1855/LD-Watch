# Implemented v1 protocol

The normative byte offsets, enums, flags and field combinations are in
[contract.md](contract.md#wire-record). This guide describes implementation and
operation; it does not introduce another wire definition.

## Framing

AF_UNIX/SOCK_SEQPACKET preserves one packet per event. Each packet is exactly
1,024 bytes, explicitly little-endian. Header bytes for v1:

```text
offset 0:  4c 44 57 31   magic LDW1
offset 4:  01 00         version 1
offset 6:  00 04         length 1024
offset 8:  02            LOAD (example)
offset 9:  00            UNKNOWN origin
```

The remaining fields include flags, PID, TID, start ticks, namespace,
timestamp/address, reserved zero bytes, executable, subject, requester and
symbol. C serializes bytes in `audit/src/ipc.c`; Go validates/decodes in
`internal/proto/event.go`. Native struct layout is not the wire format.

Invalid magic/version/length/enums/flags/reserved bytes and invalid required
field combinations are rejected. Legacy 408-byte packets are rejected rather
than guessed. Full text fields carry truncation flags; incomplete identities
must not become certain baseline evidence.

## Events and origins

- SEARCH: candidate considered by the loader; not proof of a load.
- LOAD: confirmed object, with `<main>` sentinel for the executable object.
- SYMBOL_BIND: provider in subject, requester in related, tracked symbol/address.
- OBJECT_CLOSE: lifecycle cleanup, not a load deviation.

Search origins come from loader flags. LOAD origin normally remains UNKNOWN;
a prior LIBRARY_PATH search does not prove the later load mechanism. PRELOAD
is reserved vocabulary without current affirmative source evidence.

## Endpoints and peers

Default endpoint: `/run/ldwatch/ldwatch.sock`. Collector `--socket` and absolute
sender `LDWATCH_SOCKET` must match. Relative/empty overrides are ignored.
Use a private writable parent directory for development. Collector validates
existing paths, rejects active sockets and unrelated files/symlinks, and sets
socket access to 0660. Peer credentials are retained as metadata, not proof
that application-supplied event contents are trustworthy.

The sender uses close-on-exec, bounded nonblocking sends, reconnect backoff and
fork handling. Application execution may continue when events are dropped.
Real C receiver and C-to-Go tests are recorded in [T09 evidence](t09-evidence.md).
