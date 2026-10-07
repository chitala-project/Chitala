/*
 * N1.1, the adapter's side of the channel: it writes a line into the shared
 * page, notifies the core, and waits for its answer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <microkit.h>

#define CORE 1

/* the shared page's address, written in by the Microkit tool (setvar_vaddr) */
uintptr_t ring;

static const char message[] = "receipt 1";

void init(void)
{
    microkit_dbg_puts("adapter: up\n");
    volatile char *page = (volatile char *)ring;
    for (unsigned i = 0; i < sizeof message; i++) {
        page[i] = message[i];
    }
    /* the line is in the page before the core hears of it */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    microkit_notify(CORE);
}

void notified(microkit_channel ch)
{
    if (ch != CORE) {
        microkit_dbg_puts("adapter: a notification on an unknown channel\n");
        return;
    }
    microkit_dbg_puts("adapter: the core answered\n");
    microkit_dbg_puts("N1.1 PASS: two protection domains, one channel, both ways\n");
}
