#define _GNU_SOURCE
#include "../../audit/include/audit.h"

#include <stdint.h>

/* audit.c references this from la_version; this standalone test does not. */
void ldw_ipc_init(void) {}

int main(void)
{
    la_version(LAV_CURRENT);
    ldw_write_int(UINT64_MAX);
    ldw_write_str("\n");
    ldw_write_hex(UINT64_MAX);
    return 0;
}
