#define _GNU_SOURCE
#include "../include/audit.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/*
 * ipc.c — Unix socket sender
 *
 * Sends ldwatch_event_t structs to the collector daemon over
 * /run/ldwatch/ldwatch.sock using write() directly.
 *
 * Design constraints (run inside every audited process):
 *   - No malloc
 *   - No printf
 *   - Non-blocking if the daemon is not running skip silently
 *   - Connect once per process, reuse the fd for all events
 */

/* Socket fd = -1 means not connected */
static int ldw_sock_fd = -1;

/*
 * ldw_ipc_init — connect to the collector daemon socket.
 * Called once from la_version() at audit library load time.
 * If the daemon is not running, ldw_sock_fd stays -1 and
 * ldw_ipc_send becomes a no-op.
 */
void ldw_ipc_init(void)
{
    struct sockaddr_un addr;

    ldw_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ldw_sock_fd < 0)
    {
        ldw_write_str(LDW_TAG "ipc: failed to create socket\n");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    /* copy socket path safely without strncpy */
    const char *path = LDW_SOCK_PATH;
    int i = 0;
    while (path[i] && i < (int)(sizeof(addr.sun_path) - 1))
    {
        addr.sun_path[i] = path[i];
        i++;
    }
    addr.sun_path[i] = '\0';

    if (connect(ldw_sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        /* Daemon not running — silent fail, become a no-op */
        close(ldw_sock_fd);
        ldw_sock_fd = -1;
    }
}

/*
 * ldw_get_timestamp_ns — get current time as nanoseconds since epoch.
 * Uses clock_gettime which is async-signal-safe.
 */
static uint64_t ldw_get_timestamp_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * ldw_ipc_send — send one event to the collector daemon.
 * If not connected, silently returns.
 * Uses write() in a loop to handle partial writes.
 */
void ldw_ipc_send(const ldwatch_event_t *event)
{
    if (ldw_sock_fd < 0)
        return;

    /* timestamp just before sending */
    ldwatch_event_t ev = *event;
    ev.timestamp_ns = ldw_get_timestamp_ns();

    const char *buf = (const char *)&ev;
    size_t len = sizeof(ldwatch_event_t);
    ssize_t sent = 0;

    while ((size_t)sent < len)
    {
        ssize_t n = write(ldw_sock_fd, buf + sent, len - (size_t)sent);
        if (n < 0)
        {
            /* Daemon went away; close and become no-op */
            close(ldw_sock_fd);
            ldw_sock_fd = -1;
            return;
        }
        sent += n;
    }
}
