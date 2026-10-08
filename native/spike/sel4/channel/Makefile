# N1.1: build the two protection domains and the system image.
#   make BUILD_DIR=... MICROKIT_SDK=... [MICROKIT_CONFIG=debug]
# Clang and ld.lld (tools.lock), as the Microkit SDK's examples build with LLVM=True.

MICROKIT_BOARD ?= qemu_virt_aarch64
MICROKIT_CONFIG ?= debug
ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif
ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be specified)
endif

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
# the board's architecture: an x86-64 board (H0.2's build matrix), or Arm
ARCH := $(if $(filter x86_64_%,$(MICROKIT_BOARD)),x86_64,aarch64)
CC := clang -target $(ARCH)-none-elf
LD := ld.lld
CFLAGS := -nostdlib -ffreestanding -g -O2 -Wall -Wextra -Werror $(if $(filter aarch64,$(ARCH)),-mstrict-align,) \
	-I$(BOARD_DIR)/include
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

IMAGE := $(BUILD_DIR)/loader.img

all: $(IMAGE)

$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o
	$(LD) $(LDFLAGS) $< $(LIBS) -o $@

$(IMAGE): $(BUILD_DIR)/core.elf $(BUILD_DIR)/adapter.elf channel.system
	$(MICROKIT_SDK)/bin/microkit channel.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) \
		--config $(MICROKIT_CONFIG) -o $(IMAGE) -r $(BUILD_DIR)/report.txt

.PHONY: all
