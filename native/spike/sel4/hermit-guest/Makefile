# N1.3: the Chitala image in a VM on seL4. Builds in BUILD_DIR, as libvmm's
# examples do (hermit.mk is the build directory's Makefile).
#   make BUILD_DIR=... MICROKIT_SDK=... LIBVMM=... LOADER_ELF=... IMAGE_ELF=...
# MICROKIT_SDK must have the board qemu_virt_aarch64_gicv3 (scripts/build-sdk.sh),
# LIBVMM the patches in sdk/libvmm-*.patch.

# the GICv3 board of the SDK built from source (N1.3), or the released SDK's
# GICv2 board (H0.1): BOARD=qemu_virt_aarch64
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
ifeq ($(strip $(LOADER_ELF))$(strip $(IMAGE_ELF)),)
$(error LOADER_ELF and IMAGE_ELF must be specified)
endif

export BUILD_DIR := $(abspath $(BUILD_DIR))
export MICROKIT_SDK := $(abspath $(MICROKIT_SDK))
export LIBVMM := $(abspath $(LIBVMM))
export SDDF := $(LIBVMM)/dep/sddf
export GUEST_DIR := $(abspath .)
export LOADER_ELF := $(abspath $(LOADER_ELF))
export IMAGE_ELF := $(abspath $(IMAGE_ELF))
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

$(BUILD_DIR)/Makefile: hermit.mk
	mkdir -p $(BUILD_DIR)
	cp hermit.mk $@

FORCE:
