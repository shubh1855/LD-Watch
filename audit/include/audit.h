#ifndef LDWATCH_AUDIT_H
#define LDWATCH_AUDIT_H

#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

/* Socket path */
#define LDW_SOCK_PATH "/run/ldwatch/ldwatch.sock"

/* Output prefix */
#define LDW_TAG "[ldwatch] "

/* Event types */
#define LDW_EVENT_SO_LOAD 0
#define LDW_EVENT_SYM_BIND 1
#define LDW_EVENT_SO_SEARCH 2

/* Resolution mechanisms */
#define LDW_MECH_STANDARD 0
#define LDW_MECH_LD_PRELOAD 1
#define LDW_MECH_LD_LIBPATH 2
#define LDW_MECH_RPATH 3

/* IPC event struct — shared contract between audit.so and collector */
/* Both sides must agree on this layout exactly */
/* Total size: 408 bytes */
typedef struct
{
    uint32_t pid;           /* offset   0 — process ID                      */
    uint8_t event_type;     /* offset   4 — LDW_EVENT_*                     */
    uint8_t mechanism;      /* offset   5 — LDW_MECH_*                      */
    uint8_t _pad[2];        /* offset   6 — explicit padding for alignment   */
    char so_path[256];      /* offset   8 — full SO path                    */
    char symbol[128];       /* offset 264 — symbol name (symbind only)       */
    uint64_t resolved_addr; /* offset 392 — resolved symbol address          */
    uint64_t timestamp_ns;  /* offset 400 — unix timestamp in nanoseconds    */
} ldwatch_event_t;

/* Max number of shared objects we track per process */
#define MAX_OBJECTS 256

/* Cookie → SO name mapping */
typedef struct
{
    uintptr_t *cookie;
    char name[256];
} ldw_obj_entry_t;

extern ldw_obj_entry_t ldw_obj_map[MAX_OBJECTS];
extern int ldw_obj_count;

/* Critical symbols we track */
static const char *CRITICAL_SYMBOLS[] = {
    "execve", "connect", "open", "getpwuid", "read", "write", NULL};

/* Helper: check if a symbol name is in our critical list */
static inline int ldw_is_critical(const char *name)
{
    for (int i = 0; CRITICAL_SYMBOLS[i] != NULL; i++)
    {
        const char *a = CRITICAL_SYMBOLS[i];
        const char *b = name;
        while (*a && *a == *b)
        {
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0')
            return 1;
    }
    return 0;
}

/* Helper: look up SO name by cookie */
static inline const char *ldw_cookie_to_name(uintptr_t *cookie)
{
    for (int i = 0; i < ldw_obj_count; i++)
    {
        if (ldw_obj_map[i].cookie == cookie)
            return ldw_obj_map[i].name;
    }
    return "<unknown>";
}

/* Safe write helpers */
void ldw_write_str(const char *s);
void ldw_write_int(uint64_t n);
void ldw_write_hex(uint64_t n);
void ldw_write_pid(void);

/* IPC functions */
void ldw_ipc_init(void);
void ldw_ipc_send(const ldwatch_event_t *event);

#endif /* LDWATCH_AUDIT_H */
