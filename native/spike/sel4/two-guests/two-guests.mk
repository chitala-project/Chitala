# The build directory's Makefile for N1.4 (see Makefile), after libvmm's
# examples/simple/simple.mk (BSD-2-Clause, UNSW).

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
# the system as built: two-guests.system, with the adapter's VM at
# ADAPTER_VM_PRIORITY, and each VM's MCS budget and period (µs) when given
# (N1.6 measures the core's latency under each)
# exported empty when not given: an empty value is no value
ADAPTER_VM_PRIORITY := $(or $(ADAPTER_VM_PRIORITY),100)
mcs = $(if $(1), budget="$(1)" period="$(2)",)
SYSTEM_FILE := two-guests.system
# a ZynqMP board (H0.2) takes its own system and device tree, and its core's
# VMM emulates the guest's UART and RTC as the adapter's does; the released
# SDK's GICv2 QEMU board (H0.1) takes its own, which map the GIC's virtual
# CPU interface into each VM
VARIANT := $(if $(filter zcu102 kria_k26 ultra96v2,$(MICROKIT_BOARD)),-zynqmp,$(if $(filter qemu_virt_aarch64,$(MICROKIT_BOARD)),-gicv2,))
SYSTEM_SRC := $(GUEST_DIR)/two-guests$(VARIANT).system
GUEST_DTS := $(GUEST_DIR)/guest$(VARIANT).dts
CORE_VMM_FLAGS := $(if $(filter -zynqmp,$(VARIANT)),-DGUEST_DEVICES_EMULATED -DGUEST_NAME=\"CORE\",-DGUEST_SERIAL_IRQ)
ARCH := aarch64

SDDF_CUSTOM_LIBC := 1

vpath %.c $(LIBVMM) $(GUEST_DIR)

IMAGES := vmm_core.elf vmm_adapter.elf relay.elf
ARCH_FLAGS := -target aarch64-none-elf -mstrict-align
# each guest's RAM, as two-guests.system sizes it
CORE_RAM := 0x20000000
ADAPTER_RAM := 0x10000000
# what the adapter's device tree tells its guest it has. Normally the grant;
# N1.5b sets it higher, so the guest reaches past what seL4 mapped. $(or ...)
# keeps the grant when the variable is exported empty (an unset environment).
ADAPTER_DTB_RAM := $(or $(ADAPTER_DTB_RAM),$(ADAPTER_RAM))

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

$(SYSTEM_FILE): $(SYSTEM_SRC) FORCE
	grep -q '<virtual_machine name="adapter" priority="100">' $<
	grep -q '<virtual_machine name="core" priority="100">' $<
	sed -e 's|<virtual_machine name="adapter" priority="100">|<virtual_machine name="adapter" priority="$(ADAPTER_VM_PRIORITY)"$(call mcs,$(ADAPTER_VM_BUDGET),$(ADAPTER_VM_PERIOD))>|' \
	    -e 's|<virtual_machine name="core" priority="100">|<virtual_machine name="core" priority="100"$(call mcs,$(CORE_VM_BUDGET),$(CORE_VM_PERIOD))>|' $< >$@.new
	cmp -s $@.new $@ || mv $@.new $@
	rm -f $@.new
FORCE:

loader.img: $(IMAGES) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $@ -r report.txt \
	    --capdl-json capdl.json

# one VMM, built for each guest: the core's passes the UART and its interrupt
# through; the adapter's guest gets no device of the board (N1.5a)
vmm_core.o: $(VMM_C)
	$(CC) $(CFLAGS) -DGUEST_CHANNEL $(CORE_VMM_FLAGS) -DGUEST_RAM_SIZE=$(CORE_RAM)UL -c -o $@ $<
vmm_adapter.o: $(VMM_C)
	$(CC) $(CFLAGS) -DGUEST_CHANNEL -DGUEST_DEVICES_EMULATED -DGUEST_NAME=\"ADAPTER\" \
	    -DGUEST_RAM_SIZE=$(ADAPTER_RAM)UL $(ADAPTER_VMM_EXTRA_CFLAGS) -c -o $@ $<

vmm_%.elf: vmm_%.o images_%.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

relay.o: $(GUEST_DIR)/relay.c
	$(CC) $(CFLAGS) $(RELAY_EXTRA_CFLAGS) -c -o $@ $<
relay.elf: relay.o
	$(LD) $(LDFLAGS) $< --start-group -lmicrokit -Tmicrokit.ld libsddf_util_debug.a --end-group -o $@

# each guest's device tree: its RAM, its image as the initrd, its arguments
define dtb
	sed -e "s/@RAM_SIZE@/$(2)/" \
	    -e "s/@INITRD_END@/$$(printf '0x%x' $$((0x48000000 + $$(stat -c %s $(3)))))/" \
	    -e "s/@BOOTARGS@/$(4)/" $(GUEST_DTS) \
		| $(DTC) -q -I dts -O dtb -o $(1) -
endef
core.dtb: $(GUEST_DTS) $(CORE_ELF)
	$(call dtb,$@,$(CORE_RAM),$(CORE_ELF),$(if $(CORE_ARGS),-- $(CORE_ARGS),))
adapter.dtb: $(GUEST_DTS) $(ADAPTER_ELF)
	$(call dtb,$@,$(ADAPTER_DTB_RAM),$(ADAPTER_ELF),$(if $(ADAPTER_ARGS),-- $(ADAPTER_ARGS),))

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
