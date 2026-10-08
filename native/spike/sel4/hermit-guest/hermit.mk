# The build directory's Makefile for N1.3 (see Makefile), after libvmm's
# examples/simple/simple.mk (BSD-2-Clause, UNSW).

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
# a GICv2 board takes its own system (the virtual CPU interface) and device tree
VARIANT := $(if $(filter qemu_virt_aarch64,$(MICROKIT_BOARD)),-gicv2,)
SYSTEM_FILE := $(GUEST_DIR)/hermit$(VARIANT).system
DTS_FILE := $(GUEST_DIR)/hermit$(VARIANT).dts
IMAGE_FILE := loader.img
REPORT_FILE := report.txt
ARCH := aarch64

SDDF_CUSTOM_LIBC := 1

vpath %.c $(LIBVMM) $(GUEST_DIR)

IMAGES := vmm.elf
ARCH_FLAGS := -target aarch64-none-elf -mstrict-align
CFLAGS := \
	  -ffreestanding \
	  -g3 -O3 -Wall \
	  -Wno-unused-function \
	  -DBOARD_$(MICROKIT_BOARD) \
	  -DGUEST_SERIAL_IRQ \
	  -I$(BOARD_DIR)/include \
	  -I$(LIBVMM)/include \
	  -I$(SDDF)/include \
	  -I$(SDDF)/include/sddf/util/custom_libc \
	  -I$(SDDF)/include/microkit \
	  -MD \
	  -MP \
	  $(ARCH_FLAGS)

LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := --start-group -lmicrokit -Tmicrokit.ld libvmm.a libsddf_util_debug.a --end-group

all: $(IMAGE_FILE)

vmm.elf: vmm.o images.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

-include vmm.d

$(IMAGES): libvmm.a libsddf_util_debug.a

$(IMAGE_FILE) $(REPORT_FILE): $(IMAGES) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $(IMAGE_FILE) -r $(REPORT_FILE)

vm.dtb: $(DTS_FILE) $(IMAGE_ELF)
	sed "s/@INITRD_END@/$$(printf '0x%x' $$((0x48000000 + $$(stat -c %s $(IMAGE_ELF)))))/" $< \
		| $(DTC) -q -I dts -O dtb -o $@ -

vmm.o: $(GUEST_DIR)/vmm.c
	$(CC) $(CFLAGS) -c -o $@ $<

images.o: $(LIBVMM)/tools/package_guest_images.S $(LOADER_ELF) vm.dtb $(IMAGE_ELF)
	$(CC) -c -g3 -x assembler-with-cpp \
					-DGUEST_KERNEL_IMAGE_PATH=\"$(LOADER_ELF)\" \
					-DGUEST_DTB_IMAGE_PATH=\"vm.dtb\" \
					-DGUEST_INITRD_IMAGE_PATH=\"$(IMAGE_ELF)\" \
					$(ARCH_FLAGS) \
					$(LIBVMM)/tools/package_guest_images.S -o $@

include $(LIBVMM)/vmm.mk
include $(SDDF)/util/util.mk
