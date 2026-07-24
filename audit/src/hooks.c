#define _GNU_SOURCE
#include "../include/audit.h"
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* ── Cookie → SO name map ───────────────────────────────────────────────────
 */
/*
 * la_objopen gives us a cookie (unique pointer) per loaded SO.
 * la_symbind64 gives us that same cookie to tell us which SO a symbol
 * resolved from. We store the mapping here so we can look up the name.
 */
ldw_obj_entry_t ldw_obj_map[MAX_OBJECTS];
int ldw_obj_count = 0;

/* ── Helper: safe strncpy without libc dependency ────────────────────────── */
static void ldw_copy_str(char *dst, const char *src, int max) {
  int i = 0;
  while (src && src[i] && i < max - 1) {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
}

/*
 * la_objopen — called every time ld.so loads a shared object.
 *
 * @map    : link_map for the loaded SO. map->l_name is the full path.
 * @lmid   : namespace ID (usually LM_ID_BASE)
 * @cookie : unique identifier for this SO — we store it for symbind lookup
 *
 * Return value controls which SO's symbol bindings we want to audit:
 *   LA_FLG_BINDFROM — notify when this SO references a symbol elsewhere
 *   LA_FLG_BINDTO   — notify when a symbol resolves INTO this SO
 * We return both so we catch everything.
 */
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  (void)lmid;

  /* Store cookie → name mapping for la_symbind64 to use later */
  if (ldw_obj_count < MAX_OBJECTS) {
    ldw_obj_map[ldw_obj_count].cookie = cookie;
    ldw_copy_str(ldw_obj_map[ldw_obj_count].name, map->l_name, 256);
    ldw_obj_count++;
  }

  /* Print the event */
  ldw_write_str(LDW_TAG "LOAD   pid=");
  ldw_write_pid();
  ldw_write_str(" so=");
  ldw_write_str(map->l_name[0] ? map->l_name : "<main>");
  ldw_write_str("\n");

  return LA_FLG_BINDFROM | LA_FLG_BINDTO;
}

/*
 * la_objsearch — called when ld.so searches for a shared object by name.
 * This is where we detect HOW an SO was found — standard path, LD_LIBRARY_PATH,
 * RPATH, etc. The `flag` parameter tells us the resolution mechanism.
 *
 * Key flags:
 *   LA_SER_ORIG     — original name as requested
 *   LA_SER_LIBPATH  — found via LD_LIBRARY_PATH  ← suspicious
 *   LA_SER_RUNPATH  — found via DT_RUNPATH
 *   LA_SER_DEFAULT  — found in default path (/lib, /usr/lib)
 *   LA_SER_CONFIG   — found via ldconfig cache
 *   LA_SER_SECURE   — found in secure path (setuid processes)
 *
 * Return the name unchanged to allow loading to proceed.
 * Return NULL to abort loading (we don't do this — we only observe).
 */
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
  (void)cookie;

  const char *mechanism = "standard";
  int suspicious = 0;

  if (flag & LA_SER_LIBPATH) {
    mechanism = "LD_LIBRARY_PATH";
    suspicious = 1;
  } else if (flag & LA_SER_RUNPATH) {
    mechanism = "RPATH/RUNPATH";
  } else if (flag & LA_SER_CONFIG) {
    mechanism = "ldconfig";
  } else if (flag & LA_SER_DEFAULT) {
    mechanism = "default";
  } else if (flag & LA_SER_ORIG) {
    mechanism = "original";
  }

  ldw_write_str(LDW_TAG "SEARCH pid=");
  ldw_write_pid();
  ldw_write_str(" name=");
  ldw_write_str(name);
  ldw_write_str(" mechanism=");
  ldw_write_str(mechanism);
  if (suspicious) {
    ldw_write_str(" [!] LD_LIBRARY_PATH in use");
  }
  ldw_write_str("\n");

  /* Always return name — we are observing, not blocking */
  return (char *)name;
}

/*
 * la_symbind64 — called when a symbol is resolved (bound) at runtime.
 * Only fires for SOs that returned LA_FLG_BINDFROM | LA_FLG_BINDTO
 * from la_objopen — which is all of them in our case.
 *
 * @sym     : ELF symbol struct — sym->st_value has the resolved address
 * @ndx     : symbol table index
 * @refcook : cookie of the SO that is REQUESTING the symbol
 * @defcook : cookie of the SO that PROVIDES the symbol (where it resolved to)
 * @flags   : can set LA_SYMB_NOPLTENTER to skip PLT tracing
 * @namep   : symbol name
 *
 * We only log symbols in our CRITICAL_SYMBOLS list.
 * Return the symbol value unchanged.
 */
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
                       uintptr_t *defcook, unsigned int *flags,
                       const char *symname) {
  (void)ndx;
  (void)flags;

  /* Only track symbols we care about */
  if (!ldw_is_critical(symname)) {
    return sym->st_value;
  }

  const char *from_so = ldw_cookie_to_name(refcook);
  const char *into_so = ldw_cookie_to_name(defcook);

  ldw_write_str(LDW_TAG "SYMBOL pid=");
  ldw_write_pid();
  ldw_write_str(" sym=");
  ldw_write_str(symname);
  ldw_write_str(" addr=");
  ldw_write_hex((uint64_t)sym->st_value);
  ldw_write_str(" resolved_into=");
  ldw_write_str(into_so);
  ldw_write_str(" requested_by=");
  ldw_write_str(from_so);
  ldw_write_str("\n");

  return sym->st_value;
}
