# The build directory's Makefile for N1.4 (see Makefile), after libvmm's
# examples/simple/simple.mk (BSD-2-Clause, UNSW).

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
SYSTEM_FILE := $(GUEST_DIR)/two-guests.system
ARCH := aarch64

SDDF_CUSTOM_LIBC := 1

vpath %.c $(LIBVMM) $(GUEST_DIR)

IMAGES := vmm_core.elf vmm_adapter.elf relay.elf
ARCH_FLAGS := -target aarch64-none-elf -mstrict-align
# each guest's RAM, as two-guests.system sizes it
CORE_RAM := 0x20000000
ADAPTER_RAM := 0x10000000

CFLAGS := \
	  -ffreestanding \
	  -g3 -O3 -Wall \
	  -Wno-unused-function \
	  -DBOARD_$(MICROKIT_BOARD) \
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

all: loader.img

-include vmm_core.d vmm_adapter.d relay.d

$(IMAGES): libvmm.a libsddf_util_debug.a

loader.img: $(IMAGES) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $@ -r report.txt

# one VMM, built for each guest: the core's passes the UART and its interrupt
# through; the adapter's guest gets no device of the board (N1.5a)
vmm_core.o: $(VMM_C)
	$(CC) $(CFLAGS) -DGUEST_CHANNEL -DGUEST_SERIAL_IRQ -DGUEST_RAM_SIZE=$(CORE_RAM)UL -c -o $@ $<
vmm_adapter.o: $(VMM_C)
	$(CC) $(CFLAGS) -DGUEST_CHANNEL -DGUEST_DEVICES_EMULATED -DGUEST_NAME=\"ADAPTER\" \
	    -DGUEST_RAM_SIZE=$(ADAPTER_RAM)UL -c -o $@ $<

vmm_%.elf: vmm_%.o images_%.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

relay.o: $(GUEST_DIR)/relay.c
	$(CC) $(CFLAGS) -c -o $@ $<
relay.elf: relay.o
	$(LD) $(LDFLAGS) $< --start-group -lmicrokit -Tmicrokit.ld libsddf_util_debug.a --end-group -o $@

# each guest's device tree: its RAM, its image as the initrd, its arguments
define dtb
	sed -e "s/@RAM_SIZE@/$(2)/" \
	    -e "s/@INITRD_END@/$$(printf '0x%x' $$((0x48000000 + $$(stat -c %s $(3)))))/" \
	    -e "s/@BOOTARGS@/$(4)/" $(GUEST_DIR)/guest.dts \
		| $(DTC) -q -I dts -O dtb -o $(1) -
endef
core.dtb: $(GUEST_DIR)/guest.dts $(CORE_ELF)
	$(call dtb,$@,$(CORE_RAM),$(CORE_ELF),)
adapter.dtb: $(GUEST_DIR)/guest.dts $(ADAPTER_ELF)
	$(call dtb,$@,$(ADAPTER_RAM),$(ADAPTER_ELF),$(if $(ADAPTER_ARGS),-- $(ADAPTER_ARGS),))

define images
	$(CC) -c -g3 -x assembler-with-cpp \
					-DGUEST_KERNEL_IMAGE_PATH=\"$(LOADER_ELF)\" \
					-DGUEST_DTB_IMAGE_PATH=\"$(2)\" \
					-DGUEST_INITRD_IMAGE_PATH=\"$(3)\" \
					$(ARCH_FLAGS) \
					$(LIBVMM)/tools/package_guest_images.S -o $(1)
endef
images_core.o: $(LIBVMM)/tools/package_guest_images.S $(LOADER_ELF) core.dtb $(CORE_ELF)
	$(call images,$@,core.dtb,$(CORE_ELF))
images_adapter.o: $(LIBVMM)/tools/package_guest_images.S $(LOADER_ELF) adapter.dtb $(ADAPTER_ELF)
	$(call images,$@,adapter.dtb,$(ADAPTER_ELF))

include $(LIBVMM)/vmm.mk
include $(SDDF)/util/util.mk
