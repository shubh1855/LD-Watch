#define _GNU_SOURCE
#include "../include/audit.h"
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int ldw_verbose = 1;

/*
 * la_version — first function ld.so calls into our audit library.
 * We must return LAV_CURRENT to tell the linker we support this
 * version of the audit interface. If we return anything else,
 * the linker will refuse to use our library.
 */
unsigned int la_version(unsigned int version)
{
    (void)version;
    const char *verbose = getenv("LDWATCH_VERBOSE");
    if (verbose && verbose[0] == '0' && verbose[1] == '\0')
        ldw_verbose = 0;

    if (ldw_verbose)
    {
        ldw_write_str(LDW_TAG "audit library loaded (pid=");
        ldw_write_pid();
        ldw_write_str(")\n");
    }

    /* Connect to collector daemon; no-op if not running */
    ldw_ipc_init();

    return LAV_CURRENT;
}

int ldw_verbose_enabled(void) { return ldw_verbose; }

void ldw_copy_field(char *dst, size_t dst_size, const char *src,
                    uint16_t *flags, uint16_t truncation_flag)
{
    size_t i = 0;
    if (dst_size == 0)
        return;
    while (src && src[i] && i + 1 < dst_size)
    {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    if (src && src[i] != '\0' && flags)
        *flags |= truncation_flag;
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
    /* 20 decimal digits for UINT64_MAX, plus the terminating NUL. */
    char buf[21];
    int i = 20;
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
    /* "0x", 16 hexadecimal digits, and the terminating NUL. */
    char buf[19];
    int i = 18;
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
