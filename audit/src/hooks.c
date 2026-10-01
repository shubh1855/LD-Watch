#define _GNU_SOURCE
#include "../include/audit.h"

#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

ldw_obj_entry_t ldw_obj_map[MAX_OBJECTS];
int ldw_obj_count = 0;
uint64_t ldw_obj_capacity_drops = 0;

static void ldw_zero_event(ldwatch_event_t *ev)
{
    memset(ev, 0, sizeof(*ev));
    ev->pid = (uint32_t)getpid();
    ev->tid = (uint32_t)syscall(SYS_gettid);
}

static int ldw_find_cookie(uintptr_t *cookie)
{
    for (int i = 0; i < ldw_obj_count; i++)
    {
        if (ldw_obj_map[i].cookie == cookie)
            return i;
    }
    return -1;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    const char *object_name = map->l_name[0] ? map->l_name : "<main>";
    if (ldw_obj_count < MAX_OBJECTS)
    {
        ldw_obj_map[ldw_obj_count].cookie = cookie;
        ldw_obj_map[ldw_obj_count].namespace_id = (uint64_t)lmid;
        ldw_copy_field(ldw_obj_map[ldw_obj_count].name,
                       sizeof(ldw_obj_map[ldw_obj_count].name),
                       object_name, NULL, 0);
        ldw_obj_count++;
    }
    else
    {
        ldw_obj_capacity_drops++;
        if (ldw_verbose_enabled())
            ldw_write_str(LDW_TAG "object map full; attribution degraded\n");
    }

    if (ldw_verbose_enabled())
    {
        ldw_write_str(LDW_TAG "LOAD   pid=");
        ldw_write_pid();
        ldw_write_str(" so=");
        ldw_write_str(map->l_name[0] ? map->l_name : "<main>");
        ldw_write_str("\n");
    }

    ldwatch_event_t ev;
    ldw_zero_event(&ev);
    ev.event_type = LDW_EVENT_SO_LOAD;
    ev.mechanism = LDW_MECH_UNKNOWN;
    ev.namespace_id = (uint64_t)lmid;
    if (ldw_obj_count >= MAX_OBJECTS)
        ev.flags |= LDW_FLAG_OBJECT_UNRESOLVED;
    ldw_copy_field(ev.so_path, sizeof(ev.so_path), object_name,
                   &ev.flags, LDW_FLAG_SUBJECT_TRUNCATED);
    ldw_ipc_send(&ev);
    return LA_FLG_BINDFROM | LA_FLG_BINDTO;
}

unsigned int la_objclose(uintptr_t *cookie)
{
    int index = ldw_find_cookie(cookie);
    if (index < 0)
        return 0;

    ldwatch_event_t ev;
    ldw_zero_event(&ev);
    ev.event_type = LDW_EVENT_OBJECT_CLOSE;
    ev.namespace_id = ldw_obj_map[index].namespace_id;
    ldw_copy_field(ev.so_path, sizeof(ev.so_path), ldw_obj_map[index].name,
                   &ev.flags, LDW_FLAG_SUBJECT_TRUNCATED);
    ldw_ipc_send(&ev);

    ldw_obj_count--;
    if (index != ldw_obj_count)
        ldw_obj_map[index] = ldw_obj_map[ldw_obj_count];
    return 0;
}

char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
    uint8_t mechanism = LDW_MECH_UNKNOWN;
    const char *mechanism_name = "unknown";
    if (flag & LA_SER_LIBPATH)
    {
        mechanism = LDW_MECH_LD_LIBPATH;
        mechanism_name = "LD_LIBRARY_PATH";
    }
    else if (flag & LA_SER_RUNPATH)
    {
        mechanism = LDW_MECH_RPATH;
        mechanism_name = "RPATH/RUNPATH";
    }
    else if (flag & LA_SER_CONFIG)
    {
        mechanism = LDW_MECH_CONFIG;
        mechanism_name = "ldconfig";
    }
    else if (flag & LA_SER_DEFAULT)
    {
        mechanism = LDW_MECH_STANDARD;
        mechanism_name = "default";
    }
    else if (flag & LA_SER_SECURE)
    {
        mechanism = LDW_MECH_SECURE;
        mechanism_name = "secure";
    }

    if (ldw_verbose_enabled())
    {
        ldw_write_str(LDW_TAG "SEARCH pid=");
        ldw_write_pid();
        ldw_write_str(" name=");
        ldw_write_str(name);
        ldw_write_str(" mechanism=");
        ldw_write_str(mechanism_name);
        ldw_write_str("\n");
    }

    ldwatch_event_t ev;
    ldw_zero_event(&ev);
    ev.event_type = LDW_EVENT_SO_SEARCH;
    ev.mechanism = mechanism;
    ev.namespace_id = ldw_cookie_to_namespace(cookie);
    if (ldw_find_cookie(cookie) < 0)
        ev.flags |= LDW_FLAG_OBJECT_UNRESOLVED;
    ldw_copy_field(ev.so_path, sizeof(ev.so_path), name,
                   &ev.flags, LDW_FLAG_SUBJECT_TRUNCATED);
    ldw_copy_field(ev.related_path, sizeof(ev.related_path),
                   ldw_cookie_to_name(cookie), &ev.flags,
                   LDW_FLAG_RELATED_TRUNCATED);
    ldw_ipc_send(&ev);
    return (char *)name;
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
                       uintptr_t *defcook, unsigned int *flags,
                       const char *symname)
{
    (void)ndx;
    (void)flags;
    if (!ldw_is_critical(symname))
        return sym->st_value;

    const char *from_so = ldw_cookie_to_name(refcook);
    const char *into_so = ldw_cookie_to_name(defcook);
    if (ldw_verbose_enabled())
    {
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
    }

    ldwatch_event_t ev;
    ldw_zero_event(&ev);
    ev.event_type = LDW_EVENT_SYM_BIND;
    ev.mechanism = LDW_MECH_UNKNOWN;
    ev.namespace_id = ldw_cookie_to_namespace(defcook);
    if (ldw_find_cookie(defcook) < 0 || ldw_find_cookie(refcook) < 0)
        ev.flags |= LDW_FLAG_OBJECT_UNRESOLVED;
    ev.resolved_addr = (uint64_t)sym->st_value;
    ldw_copy_field(ev.so_path, sizeof(ev.so_path), into_so,
                   &ev.flags, LDW_FLAG_SUBJECT_TRUNCATED);
    ldw_copy_field(ev.related_path, sizeof(ev.related_path), from_so,
                   &ev.flags, LDW_FLAG_RELATED_TRUNCATED);
    ldw_copy_field(ev.symbol, sizeof(ev.symbol), symname,
                   &ev.flags, LDW_FLAG_SYMBOL_TRUNCATED);
    ldw_ipc_send(&ev);
    return sym->st_value;
}
