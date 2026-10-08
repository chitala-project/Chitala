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

#ifdef RELAY_HOSTILE
/*
 * N1.5d: a hostile relay. It still cannot forge Authority — orders are signed,
 * session-bound and single-use, and receipts are bound to their order — so the
 * worst it does is make execution fail, never happen twice or unsigned.
 * RELAY_MODE selects what it does to complete messages (newline-framed JSON);
 * it reads the bytes only to tell an order (core → adapter) or a receipt
 * (adapter → core) from the rest, and leaves init and observe alone:
 *   1 D1  corrupt an order (flip a bit)       → the order is rejected
 *   2 D2  send an order twice                 → the gate executes it once
 *   4 D4  withhold an order                   → it never executes
 *   5 D5  replay a receipt to the core        → the core rejects the stale receipt
 * (D3, reordering whole messages, needs two messages in flight at once; the
 * order protocol is lockstep, one order and its reply at a time, so there is
 * never a second complete message to reorder, and each order is validated on
 * its own regardless of arrival order. It reduces to D2/D4 and is not a mode.)
 */
#ifndef RELAY_MODE
#define RELAY_MODE 0
#endif

static bool contains(const char *buf, int len, const char *needle)
{
    int nl = 0;
    while (needle[nl]) {
        nl++;
    }
    for (int i = 0; i + nl <= len; i++) {
        int j = 0;
        while (j < nl && buf[i + j] == needle[j]) {
            j++;
        }
        if (j == nl) {
            return true;
        }
    }
    return false;
}

/* Enqueue a whole message and its newline to `to`, then notify. Messages are
 * small and the queue is 64 KiB, so this does not fill. */
static void send_msg(serial_queue_handle_t *to, microkit_channel to_ch, const char *buf, int len)
{
    for (int i = 0; i < len; i++) {
        if (serial_queue_full(to, to->queue->tail)) {
            break;
        }
        serial_enqueue(to, buf[i]);
    }
    if (!serial_queue_full(to, to->queue->tail)) {
        serial_enqueue(to, '\n');
    }
    microkit_notify(to_ch);
}

static char c2a[DATA_SIZE];
static int c2a_len;

/* core → adapter: the orders. Frame complete lines and apply the order modes. */
static void hostile_c2a(void)
{
    char ch;
    while (serial_dequeue(&core_tx, &ch) == 0) {
        if (ch != '\n') {
            if (c2a_len < DATA_SIZE) {
                c2a[c2a_len++] = ch;
            }
            continue;
        }
        if (!contains(c2a, c2a_len, "\"op\":\"execute\"")) {
            send_msg(&adapter_rx, ADAPTER, c2a, c2a_len); /* init, observe: untouched */
        } else {
#if RELAY_MODE == 1
            if (c2a_len > 0) {
                c2a[c2a_len / 2] ^= 0x20; /* D1: flip a bit in the order */
            }
            send_msg(&adapter_rx, ADAPTER, c2a, c2a_len);
#elif RELAY_MODE == 2
            send_msg(&adapter_rx, ADAPTER, c2a, c2a_len); /* D2: the same order, twice */
            send_msg(&adapter_rx, ADAPTER, c2a, c2a_len);
#elif RELAY_MODE == 4
            /* D4: withhold the order; it never reaches the adapter */
#else
            send_msg(&adapter_rx, ADAPTER, c2a, c2a_len);
#endif
        }
        c2a_len = 0;
    }
}

static char a2c[DATA_SIZE];
static int a2c_len;

/* adapter → core: the replies. D5 replays a receipt. */
static void hostile_a2c(void)
{
    char ch;
    while (serial_dequeue(&adapter_tx, &ch) == 0) {
        if (ch != '\n') {
            if (a2c_len < DATA_SIZE) {
                a2c[a2c_len++] = ch;
            }
            continue;
        }
        send_msg(&core_rx, CORE, a2c, a2c_len);
#if RELAY_MODE == 5
        if (contains(a2c, a2c_len, "\"receipt\"")) {
            send_msg(&core_rx, CORE, a2c, a2c_len); /* D5: the same receipt, again */
        }
#endif
        a2c_len = 0;
    }
}
#endif /* RELAY_HOSTILE */

void notified(microkit_channel ch)
{
    /* whichever side spoke, move what can move, both ways */
    (void)ch;
#ifdef RELAY_HOSTILE
    hostile_c2a();
    hostile_a2c();
#else
    copy(&core_tx, CORE, &adapter_rx, ADAPTER);
    copy(&adapter_tx, ADAPTER, &core_rx, CORE);
#endif
}
