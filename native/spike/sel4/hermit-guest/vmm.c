/*
 * N1.3: the VMM that runs the Chitala image. It places three things in the
 * guest's RAM and starts the guest at the Hermit loader's entry point:
 *   - the device tree, at the start of RAM, where the Hermit loader reads it;
 *   - the Hermit loader, its ELF segments each at its physical address;
 *   - the Chitala image (the unikernel's ELF), as the initrd the device tree names.
 * Then it passes the UART's interrupt through (with GUEST_SERIAL_IRQ), and
 * handles the guest's faults with libvmm: the virtual GICv3, the virtual
 * timer (the guest runs on it, native/patches/), PSCI.
 *
 * With GUEST_CHANNEL (N1.4) the guest also gets a virtio console, joined
 * through two serial queues to the relay protection domain: the channel to
 * the other guest. The VMM moves bytes between the guest and the queues and
 * reads none of them.
 *
 * With GUEST_DEVICES_EMULATED (N1.5a) the guest maps no device of the board.
 * The VMM shows it a UART and an RTC where its device tree says they are:
 *   - the UART is for output only. The VMM writes each line to the system's
 *     debug console behind GUEST_NAME "| ", which the guest cannot leave out
 *     or overwrite: it cannot pass a line off as another guest's. Only
 *     printable ASCII passes; any other byte is written as \xNN, so no
 *     control byte of the guest's reaches a terminal;
 *   - the RTC is read-only. The VMM reads the board's RTC through a read-only
 *     mapping of its own, so the guest learns the time and cannot set the
 *     clock another guest reads.
 *
 * Based on libvmm's examples/simple/vmm.c (BSD-2-Clause, UNSW).
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <microkit.h>
#include <libvmm/libvmm.h>
#ifdef GUEST_CHANNEL
#include <sddf/serial/queue.h>
#include <libvmm/virtio/console.h>
#endif

#define GUEST_RAM_START_GPA 0x40000000UL
#ifndef GUEST_RAM_SIZE
#define GUEST_RAM_SIZE 0x20000000UL
#endif
#define GUEST_DTB_GPA 0x40000000UL /* the Hermit loader reads its device tree at the start of RAM */
#define GUEST_IMAGE_GPA 0x48000000UL /* the Chitala image: linux,initrd-start in hermit.dts */

#define SERIAL_IRQ_CH 1
#define SERIAL_IRQ 33

#ifdef GUEST_CHANNEL
#define CHANNEL_CH 3
/* the virtio console, where the guest's device tree says it is */
#define CHANNEL_BASE 0x0a000000UL
#define CHANNEL_SIZE 0x200UL
#define CHANNEL_IRQ 48 /* SPI 16 */
/* each queue's data: larger than the guest's largest packet (8 KiB) */
#define CHANNEL_DATA_SIZE 0x10000
uintptr_t channel_tx_queue, channel_tx_data, channel_rx_queue, channel_rx_data;
static serial_queue_handle_t channel_rx, channel_tx;
static struct virtio_console_device channel;
#endif

#ifdef GUEST_DEVICES_EMULATED
/* where the guest's device tree puts them */
#define UART_BASE 0x09000000UL
#define RTC_BASE 0x09010000UL
#define DEVICE_SIZE 0x1000UL
#define UART_DR 0x00
#define UART_FR 0x18
#define UART_FR_RXFE 0x10 /* nothing to read, ever */
#define UART_FR_TXFE 0x80 /* room to write, always */
/* the board's RTC, mapped read-only into this VMM */
uintptr_t rtc_vaddr;
static char line[160];
static size_t line_len;

static void line_out(void)
{
    line[line_len] = '\0';
    microkit_dbg_puts(GUEST_NAME "| ");
    microkit_dbg_puts(line);
    microkit_dbg_puts("\n");
    line_len = 0;
}

/* Keeps printable ASCII and writes every other byte as \xNN: control
 * characters, escape sequences, C1 controls such as 0x9b, and UTF-8 alike.
 * Nothing the guest writes is a control byte on the terminal, so nothing can
 * move the cursor back over its prefix. A log's safety comes before its
 * looks. */
static void uart_out(unsigned char c)
{
    static const char hex[] = "0123456789abcdef";
    if (c == '\n') {
        line_out();
        return;
    }
    if (line_len > sizeof(line) - 5) {
        line_out();
    }
    if (c >= 0x20 && c <= 0x7e) {
        line[line_len++] = (char)c;
    } else {
        line[line_len++] = '\\';
        line[line_len++] = 'x';
        line[line_len++] = hex[c >> 4];
        line[line_len++] = hex[c & 0xf];
    }
}

static bool uart_access(size_t vcpu_id, size_t offset, size_t fsr, seL4_UserContext *regs, void *data)
{
    if (fault_is_read(fsr)) {
        uint32_t reg = (offset & ~3UL) == UART_FR ? UART_FR_RXFE | UART_FR_TXFE : 0;
        fault_emulate_write(regs, offset, fsr, reg & fault_get_data_mask(offset, fsr));
    } else if (offset == UART_DR) {
        uart_out((unsigned char)(fault_get_data(regs, fsr) & 0xff));
    }
    /* the line, baud rate and interrupt settings mean nothing here */
    return true;
}

static bool rtc_access(size_t vcpu_id, size_t offset, size_t fsr, seL4_UserContext *regs, void *data)
{
    if (fault_is_write(fsr)) {
        LOG_VMM("the guest wrote its RTC at offset 0x%lx: refused, its clock is read-only\n", offset);
        return true;
    }
    uint32_t reg = *(volatile uint32_t *)(rtc_vaddr + (offset & ~3UL));
    fault_emulate_write(regs, offset, fsr, reg & fault_get_data_mask(offset, fsr));
    return true;
}
#endif

extern char _guest_kernel_image[], _guest_kernel_image_end[]; /* the Hermit loader's ELF */
extern char _guest_dtb_image[], _guest_dtb_image_end[];
extern char _guest_initrd_image[], _guest_initrd_image_end[]; /* the Chitala image */

uintptr_t guest_ram_vaddr;

static bool place(const char *what, uintptr_t gpa, const char *start, const char *end)
{
    size_t size = end - start;
    if (size == 0 || gpa < GUEST_RAM_START_GPA || gpa + size > GUEST_RAM_START_GPA + GUEST_RAM_SIZE) {
        LOG_VMM_ERR("%s does not fit at 0x%lx (%lu bytes)\n", what, gpa, size);
        return false;
    }
    memcpy((char *)guest_ram_vaddr + (gpa - GUEST_RAM_START_GPA), start, size);
    LOG_VMM("%s at 0x%lx, %lu bytes\n", what, gpa, size);
    return true;
}

/* The 64-bit ELF headers the loader needs (Hermit's loader is an AArch64 ELF executable). */
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} elf64_ehdr;
typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} elf64_phdr;
#define PT_LOAD 1
#define EM_AARCH64 183

/* Load each segment of the ELF executable at `start` at its physical address
 * in the guest's RAM, its bytes beyond the file zeroed. Returns its entry
 * point, or 0 if it is not one that fits. */
static uintptr_t load_elf(const char *what, const char *start, const char *end)
{
    size_t size = end - start;
    const elf64_ehdr *eh = (const elf64_ehdr *)start;
    if (size < sizeof(*eh) || memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0 || eh->e_ident[4] != 2
        || eh->e_ident[5] != 1 || eh->e_machine != EM_AARCH64 || eh->e_phentsize != sizeof(elf64_phdr)
        || eh->e_phoff > size || eh->e_phnum > (size - eh->e_phoff) / sizeof(elf64_phdr)) {
        LOG_VMM_ERR("%s is not an AArch64 ELF executable\n", what);
        return 0;
    }
    const elf64_phdr *ph = (const elf64_phdr *)(start + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) {
            continue;
        }
        uint64_t gpa = ph[i].p_paddr;
        if (ph[i].p_filesz > ph[i].p_memsz || ph[i].p_offset > size || ph[i].p_filesz > size - ph[i].p_offset
            || gpa < GUEST_RAM_START_GPA || ph[i].p_memsz > GUEST_RAM_START_GPA + GUEST_RAM_SIZE - gpa) {
            LOG_VMM_ERR("%s: segment %u does not fit\n", what, i);
            return 0;
        }
        char *dest = (char *)guest_ram_vaddr + (gpa - GUEST_RAM_START_GPA);
        memcpy(dest, start + ph[i].p_offset, ph[i].p_filesz);
        memset(dest + ph[i].p_filesz, 0, ph[i].p_memsz - ph[i].p_filesz);
        LOG_VMM("%s: segment at 0x%lx, %lu bytes\n", what, gpa, ph[i].p_memsz);
    }
    return eh->e_entry;
}

void init(void)
{
    LOG_VMM("starting \"%s\": the Chitala image under the Hermit loader\n", microkit_name);
    arch_guest_init_t args = {
        .pci_init.mmio_aperature_size = 0,
        .num_vcpus = 1,
        .num_guest_ram_regions = 1,
        .guest_ram_regions = { (struct guest_ram_region) {
            .gpa_start = GUEST_RAM_START_GPA, .size = GUEST_RAM_SIZE, .vmm_vaddr = (void *)guest_ram_vaddr } }
    };
    if (!guest_init(args)) {
        LOG_VMM_ERR("failed to initialise the guest\n");
        return;
    }
    uintptr_t entry = load_elf("Hermit loader", _guest_kernel_image, _guest_kernel_image_end);
    if (!entry || !place("device tree", GUEST_DTB_GPA, _guest_dtb_image, _guest_dtb_image_end)
        || !place("Chitala image", GUEST_IMAGE_GPA, _guest_initrd_image, _guest_initrd_image_end)) {
        return;
    }
#ifdef GUEST_SERIAL_IRQ
    if (!virq_register_passthrough(ARM_GIC_IRQ_ROUTE(GUEST_BOOT_VCPU_ID, SERIAL_IRQ), SERIAL_IRQ_CH)) {
        LOG_VMM_ERR("failed to pass the UART's interrupt through\n");
        return;
    }
#endif
#ifdef GUEST_CHANNEL
    serial_queue_init(&channel_rx, (serial_queue_t *)channel_rx_queue, CHANNEL_DATA_SIZE, (char *)channel_rx_data);
    serial_queue_init(&channel_tx, (serial_queue_t *)channel_tx_queue, CHANNEL_DATA_SIZE, (char *)channel_tx_data);
    if (!virtio_mmio_console_init(&channel, CHANNEL_BASE, CHANNEL_SIZE,
                                  ARM_GIC_IRQ_ROUTE(GUEST_BOOT_VCPU_ID, CHANNEL_IRQ), &channel_rx, &channel_tx,
                                  CHANNEL_CH, CHANNEL_CH)) {
        LOG_VMM_ERR("failed to set up the channel's virtio console\n");
        return;
    }
    LOG_VMM("channel: a virtio console at 0x%lx, joined to the relay\n", CHANNEL_BASE);
#endif
#ifdef GUEST_DEVICES_EMULATED
    if (!fault_register_vm_exception_handler(UART_BASE, DEVICE_SIZE, uart_access, NULL)
        || !fault_register_vm_exception_handler(RTC_BASE, DEVICE_SIZE, rtc_access, NULL)) {
        LOG_VMM_ERR("failed to emulate the guest's UART and RTC\n");
        return;
    }
    LOG_VMM("no device of the board in the guest: its UART writes behind \"%s| \", its RTC is read-only\n",
            GUEST_NAME);
#endif
    guest_start(entry, GUEST_DTB_GPA, GUEST_IMAGE_GPA);
#ifdef N15B_HOSTILE_VMM
    /* N1.5b, step 6: a hostile build of the adapter's VMM reaches for the
     * core's RAM, at the physical address the Microkit report gives it. This
     * VMM holds no capability to those frames, so the address is mapped
     * nowhere in its own VSpace: seL4 faults this protection domain on the
     * read, and the core is untouched. The read must never return a value. */
    LOG_VMM("N1.5b: this VMM reaches for the core's RAM at 0x%lx; it holds no capability to it\n",
            (unsigned long)N15B_CORE_PADDR);
    volatile unsigned char *p = (volatile unsigned char *)(unsigned long)N15B_CORE_PADDR;
    unsigned char stolen = *p;
    LOG_VMM_ERR("N1.5b: UNREACHED: read 0x%x from the core's RAM; isolation FAILED\n", stolen);
#endif
}

void notified(microkit_channel ch)
{
    switch (ch) {
    case SERIAL_IRQ_CH:
        if (!virq_handle_passthrough(ch)) {
            LOG_VMM_ERR("interrupt on channel %u dropped\n", ch);
        }
        break;
#ifdef GUEST_CHANNEL
    case CHANNEL_CH:
        /* the relay moved bytes in, or made room */
        virtio_console_queue_notify(&channel);
        break;
#endif
    default:
        LOG_VMM_ERR("unexpected channel %u\n", ch);
    }
}

seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    if (fault_handle(child, msginfo)) {
        *reply_msginfo = microkit_msginfo_new(0, 0);
        return seL4_True;
    }
    return seL4_False;
}
