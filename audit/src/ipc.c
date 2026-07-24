#include "../include/audit.h"

/*
 * ipc.c — Unix socket sender
 *
 * Phase 3 implementation.
 * This will send ldwatch_event_t structs to the collector daemon
 * over /run/ldwatch.sock using write() directly (no malloc, no buffering).
 *
 * For now this is intentionally empty — hooks.c writes to stderr directly.
 * When the collector daemon is ready, hooks.c will call ldw_ipc_send()
 * instead of writing to stderr.
 */

/*
 * ldw_ipc_send — send a telemetry event to the collector daemon
 * TODO: implement in Phase 3
 */
/* void ldw_ipc_send(ldwatch_event_t *event) { } */
