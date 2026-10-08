/*
 * N1.7 (bounded Bao comparison): a Bao configuration with one static
 * partition on qemu-aarch64-virt, running the minimal bare-metal guest
 * (guest/guest.S). run-n1.7.sh substitutes @GUEST_BIN@ with the built
 * guest binary's absolute path before building Bao.
 *
 * The platform (4 CPUs, RAM at 0x40000000, PL011 UART at 0x09000000, GICv3)
 * is Bao's compiled-in description for qemu-aarch64-virt; this config gives
 * the VM one CPU, a 256 MiB region, the UART, and the GICv3 addresses.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <config.h>

VM_IMAGE(guest_img, "@GUEST_BIN@")

struct config config = {

    .vmlist_size = 1,
    .vmlist = (struct vm_config[]) {
        {
            .image = {
                .base_addr = 0x40000000,
                .load_addr = VM_IMAGE_OFFSET(guest_img),
                .size = VM_IMAGE_SIZE(guest_img),
            },
            .entry = 0x40000000,
            .cpu_affinity = 0x1,

            .platform = {
                .cpu_num = 1,

                .region_num = 1,
                .regions = (struct vm_mem_region[]) {
                    { .base = 0x40000000, .size = 0x10000000 },
                },

                .dev_num = 1,
                .devs = (struct vm_dev_region[]) {
                    {   /* the PL011 UART, so the guest can write its line */
                        .pa = 0x09000000,
                        .va = 0x09000000,
                        .size = 0x1000,
                    },
                },

                .arch = {
                    .gic = {
                        .gicd_addr = 0x08000000,
                        .gicr_addr = 0x080A0000,
                    },
                },
            },
        },
    },
};
