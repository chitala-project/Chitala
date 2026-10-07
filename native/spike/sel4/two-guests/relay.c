/*
 * N1.4: the relay between the two guests' channels. It copies bytes from
 * what one guest's VMM writes to what the other's reads, both ways, and does
 * nothing else: it parses nothing, authorises nothing, and holds no key.
 * The guests treat it as hostile transport (native/src/channel.rs): signed,
 * session-bound, single-use orders (spec 19) mean a relay that lies can only
 * make execution fail.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>
#include <sddf/serial/queue.h>

#define CORE 1
#define ADAPTER 2
#define DATA_SIZE 0x10000

/* each guest's channel: the queue its VMM writes (tx) and the one it reads (rx) */
uintptr_t core_tx_queue, core_tx_data, core_rx_queue, core_rx_data;
uintptr_t adapter_tx_queue, adapter_tx_data, adapter_rx_queue, adapter_rx_data;

static serial_queue_handle_t core_tx, core_rx, adapter_tx, adapter_rx;

/* Move what is waiting in `from` into `to`, as far as it fits. */
static void copy(serial_queue_handle_t *from, microkit_channel from_ch, serial_queue_handle_t *to,
                 microkit_channel to_ch)
{
    bool moved = false;
    char c;
    while (!serial_queue_full(to, to->queue->tail) && serial_dequeue(from, &c) == 0) {
        serial_enqueue(to, c);
        moved = true;
    }
    if (moved) {
        microkit_notify(to_ch);
    }
    /* the reader's queue is full: have it tell us when it has room */
    if (!serial_queue_empty(from, from->queue->head)) {
        serial_request_consumer_signal(to);
    }
    /* the writer asked to hear when its queue has room again */
    if (moved && serial_require_consumer_signal(from)) {
        serial_cancel_consumer_signal(from);
        microkit_notify(from_ch);
    }
}

void init(void)
{
    serial_queue_init(&core_tx, (serial_queue_t *)core_tx_queue, DATA_SIZE, (char *)core_tx_data);
    serial_queue_init(&core_rx, (serial_queue_t *)core_rx_queue, DATA_SIZE, (char *)core_rx_data);
    serial_queue_init(&adapter_tx, (serial_queue_t *)adapter_tx_queue, DATA_SIZE, (char *)adapter_tx_data);
    serial_queue_init(&adapter_rx, (serial_queue_t *)adapter_rx_queue, DATA_SIZE, (char *)adapter_rx_data);
    microkit_dbg_puts("RELAY|INFO: up: copying bytes between the two guests' channels\n");
}

void notified(microkit_channel ch)
{
    /* whichever side spoke, move what can move, both ways */
    (void)ch;
    copy(&core_tx, CORE, &adapter_rx, ADAPTER);
    copy(&adapter_tx, ADAPTER, &core_rx, CORE);
}
