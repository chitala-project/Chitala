# N1.4: the core's guest and the adapter host's guest on seL4, joined by a
# relay. Builds in BUILD_DIR, as libvmm's examples do (two-guests.mk is the
# build directory's Makefile).
#   make BUILD_DIR=... MICROKIT_SDK=... LIBVMM=... LOADER_ELF=... CORE_ELF=... ADAPTER_ELF=...
#        [ADAPTER_ARGS="--disappear-on-execute 4"] [CORE_ARGS="--latency 2"]
#        [ADAPTER_VM_PRIORITY=99] [CORE_VM_BUDGET=1000 CORE_VM_PERIOD=2000] [ADAPTER_VM_BUDGET=... ADAPTER_VM_PERIOD=...]
# MICROKIT_SDK must have the board qemu_virt_aarch64_gicv3 (scripts/build-sdk.sh),
# LIBVMM the patches in sdk/libvmm-*.patch.

# the GICv3 QEMU board of the SDK built from source (N1.4 to N1.6), or a
# ZynqMP board of the released SDK, built for its static evidence (H0.2)
export MICROKIT_BOARD := $(or $(BOARD),qemu_virt_aarch64_gicv3)
export MICROKIT_CONFIG ?= debug
ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif
ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be specified)
endif
ifeq ($(strip $(LIBVMM)),)
$(error LIBVMM must be specified)
endif
ifeq ($(strip $(LOADER_ELF))$(strip $(CORE_ELF))$(strip $(ADAPTER_ELF)),)
$(error LOADER_ELF, CORE_ELF and ADAPTER_ELF must be specified)
endif

export BUILD_DIR := $(abspath $(BUILD_DIR))
export MICROKIT_SDK := $(abspath $(MICROKIT_SDK))
export LIBVMM := $(abspath $(LIBVMM))
export SDDF := $(LIBVMM)/dep/sddf
export GUEST_DIR := $(abspath .)
export VMM_C := $(abspath ../hermit-guest/vmm.c)
export LOADER_ELF := $(abspath $(LOADER_ELF))
export CORE_ELF := $(abspath $(CORE_ELF))
export ADAPTER_ELF := $(abspath $(ADAPTER_ELF))
export ADAPTER_ARGS
export CORE_ARGS
export ADAPTER_VM_PRIORITY
export ADAPTER_DTB_RAM
export ADAPTER_VMM_EXTRA_CFLAGS
export RELAY_EXTRA_CFLAGS
export CORE_VM_BUDGET CORE_VM_PERIOD ADAPTER_VM_BUDGET ADAPTER_VM_PERIOD
export CC := clang
export LD := ld.lld
export AS := llvm-as
export AR := llvm-ar
export OBJCOPY := llvm-objcopy
export DTC := dtc
export RANLIB := llvm-ranlib
export MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

all: $(BUILD_DIR)/Makefile FORCE
	$(MAKE) -C $(BUILD_DIR) loader.img

$(BUILD_DIR)/Makefile: two-guests.mk
	mkdir -p $(BUILD_DIR)
	cp two-guests.mk $@

FORCE:
