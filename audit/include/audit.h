#ifndef LDWATCH_AUDIT_H
#define LDWATCH_AUDIT_H

#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

/* Socket path and wire contract */
#define LDW_SOCK_PATH "/run/ldwatch/ldwatch.sock"
#define LDW_SOCKET_ENV "LDWATCH_SOCKET"
#define LDW_WIRE_VERSION 1
#define LDW_WIRE_RECORD_SIZE 1024

/* Output prefix */
#define LDW_TAG "[ldwatch] "

/* Event types */
#define LDW_EVENT_SO_SEARCH 1
#define LDW_EVENT_SO_LOAD 2
#define LDW_EVENT_SYM_BIND 3
#define LDW_EVENT_OBJECT_CLOSE 4

/* Resolution mechanisms */
#define LDW_MECH_UNKNOWN 0
#define LDW_MECH_STANDARD 1
#define LDW_MECH_LD_PRELOAD 2
#define LDW_MECH_LD_LIBPATH 3
#define LDW_MECH_RPATH 4
#define LDW_MECH_CONFIG 5
#define LDW_MECH_SECURE 6

/* Record flags. */
#define LDW_FLAG_EXE_TRUNCATED  (1u << 0)
#define LDW_FLAG_SUBJECT_TRUNCATED (1u << 1)
#define LDW_FLAG_RELATED_TRUNCATED (1u << 2)
#define LDW_FLAG_SYMBOL_TRUNCATED (1u << 3)
#define LDW_FLAG_EXE_UNRESOLVED (1u << 4)
#define LDW_FLAG_START_UNRESOLVED (1u << 5)
#define LDW_FLAG_OBJECT_UNRESOLVED (1u << 6)

/* Semantic event. ipc.c serializes this explicitly; this is not a wire struct. */
typedef struct
{
    uint32_t pid;           /* offset   0 — process ID                      */
    uint32_t tid;           /* callback thread ID                           */
    uint8_t event_type;     /* LDW_EVENT_*                                  */
    uint8_t mechanism;      /* origin / LDW_MECH_*                          */
    uint16_t flags;         /* LDW_FLAG_*                                   */
    uint64_t process_start_ticks;
    uint64_t namespace_id;
    uint64_t resolved_addr;
    uint64_t timestamp_ns;
    char exe_path[256];
    char so_path[384];      /* subject path                                 */
    char related_path[256]; /* requester object for search/symbol events    */
    char symbol[64];
} ldwatch_event_t;

/* Max number of shared objects we track per process */
#define MAX_OBJECTS 256

/* Cookie → SO name mapping */
typedef struct
{
    uintptr_t *cookie;
    uint64_t namespace_id;
    char name[384];
} ldw_obj_entry_t;

extern ldw_obj_entry_t ldw_obj_map[MAX_OBJECTS];
extern int ldw_obj_count;
extern uint64_t ldw_obj_capacity_drops;
extern uint64_t ldw_ipc_drops;
extern uint64_t ldw_ipc_reconnect_failures;

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

static inline uint64_t ldw_cookie_to_namespace(uintptr_t *cookie)
{
    for (int i = 0; i < ldw_obj_count; i++)
    {
        if (ldw_obj_map[i].cookie == cookie)
            return ldw_obj_map[i].namespace_id;
    }
    return 0;
}

/* Safe write helpers */
void ldw_write_str(const char *s);
void ldw_write_int(uint64_t n);
void ldw_write_hex(uint64_t n);
void ldw_write_pid(void);
int ldw_verbose_enabled(void);
void ldw_copy_field(char *dst, size_t dst_size, const char *src,
                    uint16_t *flags, uint16_t truncation_flag);

/* IPC functions */
void ldw_ipc_init(void);
void ldw_ipc_send(const ldwatch_event_t *event);

#endif /* LDWATCH_AUDIT_H */
