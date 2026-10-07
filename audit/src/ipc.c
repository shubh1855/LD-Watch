#define _GNU_SOURCE
#include "../include/audit.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* The semantic event is serialized explicitly; no native struct crosses IPC. */
static _Atomic int ldw_sock_fd = -1;
static uint32_t ldw_owner_pid;
static uint64_t ldw_next_retry_ns;
static char ldw_exe_path[256];
static uint64_t ldw_process_start_ticks;
static int ldw_identity_ready;
static int ldw_exe_truncated;
uint64_t ldw_ipc_drops;
uint64_t ldw_ipc_reconnect_failures;

static uint64_t ldw_clock_ns(clockid_t clock_id)
{
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t ldw_parse_start_ticks(void)
{
    char buf[4096];
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t length = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (length <= 0)
        return 0;
    buf[length] = '\0';

    char *state = strrchr(buf, ')');
    if (!state || state[1] != ' ')
        return 0;
    char *p = state + 2; /* field 3, process state */
    for (int field = 3; field <= 22; field++)
    {
        while (*p == ' ')
            p++;
        if (!*p)
            return 0;
        uint64_t value = 0;
        while (*p >= '0' && *p <= '9')
        {
            value = value * 10 + (uint64_t)(*p - '0');
            p++;
        }
        if (field == 22)
            return value;
        while (*p && *p != ' ')
            p++;
    }
    return 0;
}

static void ldw_init_identity(void)
{
    if (ldw_identity_ready)
        return;
    ssize_t length = readlink("/proc/self/exe", ldw_exe_path,
                             sizeof(ldw_exe_path) - 1);
    if (length < 0)
        ldw_exe_path[0] = '\0';
    else
    {
        ldw_exe_path[length] = '\0';
        ldw_exe_truncated = length == (ssize_t)(sizeof(ldw_exe_path) - 1);
    }
    ldw_process_start_ticks = ldw_parse_start_ticks();
    ldw_identity_ready = 1;
}

static void ldw_put16(unsigned char *dst, uint16_t value)
{
    dst[0] = (unsigned char)value;
    dst[1] = (unsigned char)(value >> 8);
}

static void ldw_put32(unsigned char *dst, uint32_t value)
{
    for (int i = 0; i < 4; i++)
        dst[i] = (unsigned char)(value >> (8 * i));
}

static void ldw_put64(unsigned char *dst, uint64_t value)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (unsigned char)(value >> (8 * i));
}

static void ldw_serialize(const ldwatch_event_t *event, unsigned char *wire)
{
    memset(wire, 0, LDW_WIRE_RECORD_SIZE);
    wire[0] = 'L';
    wire[1] = 'D';
    wire[2] = 'W';
    wire[3] = '1';
    ldw_put16(wire + 4, LDW_WIRE_VERSION);
    ldw_put16(wire + 6, LDW_WIRE_RECORD_SIZE);
    wire[8] = event->event_type;
    wire[9] = event->mechanism;
    ldw_put16(wire + 10, event->flags);
    ldw_put32(wire + 12, event->pid);
    ldw_put32(wire + 16, event->tid);
    ldw_put64(wire + 20, event->process_start_ticks);
    ldw_put64(wire + 28, event->namespace_id);
    ldw_put64(wire + 36, event->timestamp_ns);
    ldw_put64(wire + 44, event->resolved_addr);
    memcpy(wire + 64, event->exe_path, sizeof(event->exe_path));
    memcpy(wire + 320, event->so_path, sizeof(event->so_path));
    memcpy(wire + 704, event->related_path, sizeof(event->related_path));
    memcpy(wire + 960, event->symbol, sizeof(event->symbol));
}

static const char *ldw_socket_path(void)
{
    const char *configured = getenv(LDW_SOCKET_ENV);
    if (configured && configured[0] == '/')
        return configured;
    return LDW_SOCK_PATH;
}

static void ldw_drop_socket(int fd)
{
    int expected = fd;
    if (atomic_compare_exchange_strong(&ldw_sock_fd, &expected, -1))
        close(fd);
}

/* Connect at most once per second while the collector is unavailable. */
void ldw_ipc_init(void)
{
    uint32_t pid = (uint32_t)getpid();
    uint64_t now = ldw_clock_ns(CLOCK_MONOTONIC);
    if (now && now < ldw_next_retry_ns)
        return;
    ldw_next_retry_ns = now ? now + 1000000000ULL : 0;
    ldw_init_identity();

    const char *path = ldw_socket_path();
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= sizeof(addr.sun_path))
    {
        ldw_ipc_reconnect_failures++;
        return;
    }
    memcpy(addr.sun_path, path, path_len + 1);

    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
    {
        ldw_ipc_reconnect_failures++;
        return;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        ldw_ipc_reconnect_failures++;
        return;
    }
    atomic_store(&ldw_sock_fd, fd);
    ldw_owner_pid = pid;
}

void ldw_ipc_send(const ldwatch_event_t *event)
{
    if (!event)
        return;

    uint32_t pid = (uint32_t)getpid();
    if (ldw_owner_pid != 0 && ldw_owner_pid != pid)
    {
        int inherited = atomic_exchange(&ldw_sock_fd, -1);
        if (inherited >= 0)
            close(inherited);
        ldw_identity_ready = 0;
        ldw_process_start_ticks = 0;
        ldw_exe_truncated = 0;
        ldw_owner_pid = 0;
        /* The parent's retry deadline must not delay the child's first send.
         * A failed child connection will establish its own backoff. */
        ldw_next_retry_ns = 0;
    }
    if (atomic_load(&ldw_sock_fd) < 0)
        ldw_ipc_init();

    int fd = atomic_load(&ldw_sock_fd);
    if (fd < 0)
        return;

    ldwatch_event_t copy = *event;
    copy.pid = pid;
    if (copy.tid == 0)
        copy.tid = (uint32_t)syscall(SYS_gettid);
    if (copy.process_start_ticks == 0)
    {
        copy.process_start_ticks = ldw_process_start_ticks;
        if (copy.process_start_ticks == 0)
            copy.flags |= LDW_FLAG_START_UNRESOLVED;
    }
    if (copy.timestamp_ns == 0)
        copy.timestamp_ns = ldw_clock_ns(CLOCK_REALTIME);
    if (copy.exe_path[0] == '\0')
    {
        memcpy(copy.exe_path, ldw_exe_path, sizeof(copy.exe_path));
        if (ldw_exe_path[0] == '\0')
            copy.flags |= LDW_FLAG_EXE_UNRESOLVED;
        if (ldw_exe_truncated)
            copy.flags |= LDW_FLAG_EXE_TRUNCATED;
    }

    unsigned char wire[LDW_WIRE_RECORD_SIZE];
    ldw_serialize(&copy, wire);
    ssize_t sent = send(fd, wire, sizeof(wire), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != (ssize_t)sizeof(wire))
    {
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            ldw_ipc_drops++;
            return;
        }
        ldw_ipc_drops++;
        ldw_drop_socket(fd);
    }
}
