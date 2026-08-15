#define _GNU_SOURCE
#include "../include/audit.h"
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/*
 * la_version — first function ld.so calls into our audit library.
 * We must return LAV_CURRENT to tell the linker we support this
 * version of the audit interface. If we return anything else,
 * the linker will refuse to use our library.
 */
unsigned int la_version(unsigned int version)
{
    (void)version;
    ldw_write_str(LDW_TAG "audit library loaded (pid=");
    ldw_write_pid();
    ldw_write_str(")\n");

    /* Connect to collector daemon; no-op if not running */
    ldw_ipc_init();

    return LAV_CURRENT;
}

/* Safe write helpers */

/*
 * We never use printf/fprintf inside audit hooks.
 * Reason: the audit library runs inside every audited process.
 * printf uses malloc internally, which can cause re-entrancy issues
 * when we are auditing a process that is itself allocating memory.
 * write() is async-signal-safe and has no such problem.
 */

void ldw_write_str(const char *s)
{
    if (!s)
        return;
    size_t len = 0;
    while (s[len])
        len++;
    write(STDERR_FILENO, s, len);
}

void ldw_write_int(uint64_t n)
{
    char buf[20];
    int i = 19;
    buf[i] = '\0';
    if (n == 0)
    {
        buf[--i] = '0';
    } else
    {
        while (n > 0)
        {
            buf[--i] = '0' + (n % 10);
            n /= 10;
        }
    }
    ldw_write_str(&buf[i]);
}

void ldw_write_hex(uint64_t n)
{
    static const char hex[] = "0123456789abcdef";
    char buf[18];
    int i = 17;
    buf[i] = '\0';
    if (n == 0)
    {
        buf[--i] = '0';
    } else
    {
        while (n > 0)
        {
            buf[--i] = hex[n & 0xf];
            n >>= 4;
        }
    }
    /* prepend 0x */
    buf[--i] = 'x';
    buf[--i] = '0';
    ldw_write_str(&buf[i]);
}

void ldw_write_pid(void) { ldw_write_int((uint64_t)getpid()); }
