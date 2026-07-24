#ifndef LDWATCH_AUDIT_H
#define LDWATCH_AUDIT_H

#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

/* ── Output prefix ───────────────────────────────────────────────────────── */
#define LDW_TAG "[ldwatch] "

/* ── Max number of shared objects we track per process ───────────────────── */
#define MAX_OBJECTS 256

/* ── Cookie → SO name mapping ────────────────────────────────────────────── */
/* Used by la_objopen to store mappings, and la_symbind64 to look them up    */
typedef struct {
  uintptr_t *cookie;
  char name[256];
} ldw_obj_entry_t;

/* Defined in hooks.c, used across hooks */
extern ldw_obj_entry_t ldw_obj_map[MAX_OBJECTS];
extern int ldw_obj_count;

/* ── Critical symbols we track ───────────────────────────────────────────── */
/* la_symbind64 only fires alerts for these                                  */
static const char *CRITICAL_SYMBOLS[] = {
    "execve", "connect", "open", "getpwuid",
    "read",   "write",   NULL /* sentinel */
};

/* ── Helper: check if a symbol name is in our critical list ─────────────── */
static inline int ldw_is_critical(const char *name) {
  for (int i = 0; CRITICAL_SYMBOLS[i] != NULL; i++) {
    const char *a = CRITICAL_SYMBOLS[i];
    const char *b = name;
    while (*a && *a == *b) {
      a++;
      b++;
    }
    if (*a == '\0' && *b == '\0')
      return 1;
  }
  return 0;
}

/* ── Helper: look up SO name by cookie ───────────────────────────────────── */
static inline const char *ldw_cookie_to_name(uintptr_t *cookie) {
  for (int i = 0; i < ldw_obj_count; i++) {
    if (ldw_obj_map[i].cookie == cookie)
      return ldw_obj_map[i].name;
  }
  return "<unknown>";
}

/* ── Safe write helpers (no malloc, no printf in hot path) ───────────────── */
/* We use write() directly — safer inside audit hooks than fprintf           */
void ldw_write_str(const char *s);
void ldw_write_int(uint64_t n);
void ldw_write_hex(uint64_t n);
void ldw_write_pid(void);

#endif /* LDWATCH_AUDIT_H */
