#define _GNU_SOURCE
#include "../../audit/include/audit.h"

#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Freeze only the sender's monotonic clock: scheduling cannot accidentally
 * let the inherited one-second retry deadline expire and hide the bug. */
int __real_clock_gettime(clockid_t clock_id, struct timespec *ts);
int __wrap_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
    if (clock_id == CLOCK_MONOTONIC)
    {
        ts->tv_sec = 10;
        ts->tv_nsec = 0;
        return 0;
    }
    return __real_clock_gettime(clock_id, ts);
}

static uint64_t little_endian(const unsigned char *p, size_t size)
{
    uint64_t value = 0;
    for (size_t i = 0; i < size; i++)
        value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static void readable(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 1000) != 1 || !(p.revents & POLLIN))
    {
        fprintf(stderr, "missing immediate fork telemetry on fd %d\n", fd);
        exit(1);
    }
}

static void verify_record(int fd, pid_t pid)
{
    unsigned char wire[LDW_WIRE_RECORD_SIZE + 1];
    readable(fd);
    assert(recv(fd, wire, sizeof(wire), 0) == LDW_WIRE_RECORD_SIZE);
    assert(memcmp(wire, "LDW1", 4) == 0);
    assert(little_endian(wire + 4, 2) == LDW_WIRE_VERSION);
    assert(little_endian(wire + 6, 2) == LDW_WIRE_RECORD_SIZE);
    assert(wire[8] == LDW_EVENT_SO_LOAD);
    assert(little_endian(wire + 12, 4) == (uint32_t)pid);
    assert(little_endian(wire + 16, 4) == (uint32_t)pid);
    assert(little_endian(wire + 20, 8) != 0);
    assert(!(little_endian(wire + 10, 2) &
             (LDW_FLAG_START_UNRESOLVED | LDW_FLAG_EXE_UNRESOLVED)));
    assert(wire[64] == '/');
    assert(strcmp((const char *)wire + 320, "/test/fork-library.so") == 0);

    struct ucred peer;
    socklen_t length = sizeof(peer);
    assert(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0);
    assert(peer.pid == pid);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    assert(strlen(argv[1]) < sizeof(address.sun_path));
    strcpy(address.sun_path, argv[1]);
    assert(setenv(LDW_SOCKET_ENV, argv[1], 1) == 0);
    int server = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    assert(server >= 0);
    assert(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(server, 4) == 0);

    ldwatch_event_t event = {.event_type = LDW_EVENT_SO_LOAD};
    strcpy(event.so_path, "/test/fork-library.so");
    ldw_ipc_init();
    ldw_ipc_send(&event);
    readable(server);
    int parent_conn = accept(server, NULL, NULL);
    assert(parent_conn >= 0);
    verify_record(parent_conn, getpid());

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        close(server);
        close(parent_conn);
        ldw_ipc_send(&event); /* No exec or delay before the child's first event. */
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    readable(server);
    int child_conn = accept(server, NULL, NULL);
    assert(child_conn >= 0);
    verify_record(child_conn, child);

    /* The child's reconnect must not damage the parent's existing connection. */
    ldw_ipc_send(&event);
    verify_record(parent_conn, getpid());
    close(child_conn);
    close(parent_conn);
    close(server);
    assert(unlink(argv[1]) == 0);
    puts("FORK_TELEMETRY_OK");
    return 0;
}
