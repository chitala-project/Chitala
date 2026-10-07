/*
 * N1.1, the core's side of the channel: it reads what the adapter wrote in the
 * shared page, which it maps read-only, and answers by notification.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <microkit.h>

#define ADAPTER 1
#define LINE 64

/* the shared page's address, written in by the Microkit tool (setvar_vaddr) */
uintptr_t ring;

void init(void)
{
    microkit_dbg_puts("core: up\n");
}

void notified(microkit_channel ch)
{
    if (ch != ADAPTER) {
        microkit_dbg_puts("core: a notification on an unknown channel\n");
        return;
    }
    /* what the adapter wrote before it notified is visible from here */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    char line[LINE + 1];
    const volatile char *page = (const volatile char *)ring;
    for (int i = 0; i < LINE; i++) {
        line[i] = page[i];
    }
    line[LINE] = 0;
    microkit_dbg_puts("core: from the adapter: ");
    microkit_dbg_puts(line);
    microkit_dbg_puts("\n");
    microkit_notify(ADAPTER);
}
