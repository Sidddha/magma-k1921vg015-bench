# =============================================================================
# Makefile for magma_workbench (NIIET K1921VG015 bsp board)
#
# Self-contained: everything this project needs (system headers, platform
# startup/init sources, linker script, debugger configs) lives under this
# directory. The RISC-V toolchain and OpenOCD themselves are NOT bundled —
# clone this project, then build/flash by pointing COMPILER_PATH and
# OPENOCD_PATH at wherever you have them installed, e.g.:
#
#   make COMPILER_PATH=/path/to/xpack-riscv-none-elf-gcc/bin/
#   make flash OPENOCD_PATH=/path/to/xpack-openocd/bin/openocd
# =============================================================================

TARGET_NAME = magma_bench
BUILD_NAME  = build
BUILD_PATH  = ./$(BUILD_NAME)

# Default paths assume this project still lives two levels under the same
# workspace root as SovaHub (../../toolchain, same as SovaHub's makefile).
# Override on the command line if you cloned it anywhere else:
#   make COMPILER_PATH=/opt/xpack-riscv-none-elf-gcc-15.2.0-1/bin/
COMPILER_PATH ?= ../../toolchain/xpack-riscv-none-elf-gcc-15.2.0-1/bin/

APP_PATH      = .
SOURCES_PATH  = ./platform/source
INC_PATH      = ./platform/include
LINKER_PATH   = ./platform/ldscripts

# ==============================================================================
# Flash / Debug
# ==============================================================================

OPENOCD_PATH      ?= ../../toolchain/xpack-openocd-k1921vk-0.12.0-k1921vk/bin/openocd
OPENOCD_INIT_PATH ?= ./init
OPENOCD_IFACE_CFG ?= init/onboard_ftdi.cfg
FLASH_IMAGE       ?= $(BUILD_PATH)/$(TARGET_NAME).elf

# ==============================================================================
# Toolchain
# ==============================================================================

CROSS_PREFIX ?= $(COMPILER_PATH)riscv-none-elf-

CC      := $(CROSS_PREFIX)gcc
LD      := $(CROSS_PREFIX)ld
OBJCOPY := $(CROSS_PREFIX)objcopy
OBJDUMP := $(CROSS_PREFIX)objdump
SIZE    := $(CROSS_PREFIX)size
GDB     := $(CROSS_PREFIX)gdb

# ==============================================================================
# Architecture & ABI
# ==============================================================================

MARCH := rv32imfc_zicsr
MABI  := ilp32f

# ==============================================================================
# Paths & libraries
# ==============================================================================

INCLUDE_FOLDER = \
	-I$(INC_PATH) \
	-I$(SOURCES_PATH)

LIB_PATHS = \
	-L$(LINKER_PATH) \
	-L$(COMPILER_PATH)../riscv-none-elf/lib/rv32if_zicsr/ilp32f \
	-L$(COMPILER_PATH)../lib/gcc/riscv-none-elf/15.2.0/rv32if_zicsr/ilp32f

LIBS = -lc_nano -lg_nano -lgcc

LD_SCRIPT = $(LINKER_PATH)/k1921vg015_flash.ld

# ==============================================================================
# Flags
# ==============================================================================

# 50 MHz core clock from PLL0 (HSECLK=24 MHz x FBDIV=100 / REFDIV=2 /
# PD0A+1=6 / PD0B+1=4) — see main.c's own header comment.
DEFINES = \
	-DHSECLK_VAL=24000000 \
	-DSYSCLK_PLL \
	-DCKO_NONE \
	-DRTC_LSE \
	-DDEBUG

CFLAGS = \
	-c -Wall -Os -g -ggdb3 \
	$(DEFINES) \
	-march=$(MARCH) -mabi=$(MABI) \
	$(INCLUDE_FOLDER) \
	-std=gnu11 -MMD -MP

LDFLAGS = \
	-T $(LD_SCRIPT) \
	-Map=$(BUILD_PATH)/$(TARGET_NAME).map \
	-static -march=$(MARCH) -melf32lriscv \
	$(LIB_PATHS) $(LIBS)

# ==============================================================================
# Source files
# ==============================================================================

SRC_C = $(wildcard $(APP_PATH)/*.c) \
        $(wildcard $(SOURCES_PATH)/*.c)

SRC_S = $(wildcard $(SOURCES_PATH)/*.S)

ALL_SRC = $(SRC_C) $(SRC_S)

# Object & dependency files (preserve directory structure)
OBJ_FILES = $(patsubst %.c,  $(BUILD_PATH)/%.o, $(ALL_SRC:.S=.c))
OBJ_FILES := $(patsubst %.S, $(BUILD_PATH)/%.o, $(OBJ_FILES))

DEP_FILES = $(OBJ_FILES:.o=.d)

-include $(DEP_FILES)

# ==============================================================================
# Rules
# ==============================================================================

.PHONY: all clean size hex help debug debug-server debug-gdb attach flash erase

all: header directories $(BUILD_PATH)/$(TARGET_NAME).elf $(BUILD_PATH)/$(TARGET_NAME).dump hex size

directories:
	@mkdir -p $(BUILD_PATH)
	@for src in $(ALL_SRC); do \
		mkdir -p $(BUILD_PATH)/$$(dirname "$$src"); \
	done

header:
	@echo "magma_workbench — K1921VG015 bsp board (COMPILER_PATH=$(COMPILER_PATH))"

# Pattern rule - C files
$(BUILD_PATH)/%.o : %.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Pattern rule - Assembly files
$(BUILD_PATH)/%.o : %.S
	@mkdir -p $(@D)
	@echo "  AS      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Linking
$(BUILD_PATH)/$(TARGET_NAME).elf: $(OBJ_FILES)
	@echo "  LD      $@"
	@$(LD) -o $@ $^ $(LDFLAGS)
	@echo "  ... done"

# Disassembly
$(BUILD_PATH)/$(TARGET_NAME).dump: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "  OBJDUMP $@"
	@$(OBJDUMP) -d -S -l -t $< > $@
	@echo "  ... done"

hex: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "  OBJCOPY $(BUILD_PATH)/$(TARGET_NAME).hex"
	@$(OBJCOPY) -O ihex $< $(BUILD_PATH)/$(TARGET_NAME).hex
	@echo "  ... done"

size: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "=============================================="
	@$(SIZE) --format=berkeley $<
	@echo "=============================================="
	@$(eval FLASH_TOTAL=1048576)  # 1MB Flash in bytes
	@$(eval RAM_TOTAL=262144)      # 256KB RAM in bytes
	@$(eval FLASH_USED=$(shell $(SIZE) $< | tail -1 | awk '{print $$1 + $$2}'))
	@$(eval RAM_USED=$(shell $(SIZE) $< | tail -1 | awk '{print $$2 + $$3}'))
	@echo "Memory Usage:"
	@printf "  Flash: %6d / %6d bytes (%3d%%)\n" $(FLASH_USED) $(FLASH_TOTAL) $$(($(FLASH_USED)*100/$(FLASH_TOTAL)))
	@printf "  RAM:   %6d / %6d bytes (%3d%%)\n" $(RAM_USED) $(RAM_TOTAL) $$(($(RAM_USED)*100/$(RAM_TOTAL)))
	@echo "=============================================="

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_PATH) *.o *.elf *.hex *.map
	@echo "Done."

rebuild: clean all

erase:
	@echo "Erasing entire flash memory..."
	$(OPENOCD_PATH) -s $(OPENOCD_INIT_PATH) \
		-f $(OPENOCD_IFACE_CFG) \
		-f $(OPENOCD_INIT_PATH)/k1921vg015.cfg \
		-c "init" \
		-c "reset halt" \
		-c "flash erase_sector 0 0 last" \
		-c "reset run" \
		-c "exit"
	@echo "...ERASE DONE"

flash: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "FLASHING " $(FLASH_IMAGE)
	$(OPENOCD_PATH) -s $(OPENOCD_INIT_PATH) \
		-f $(OPENOCD_IFACE_CFG) \
		-f $(OPENOCD_INIT_PATH)/k1921vg015.cfg \
		-c "program $(FLASH_IMAGE) reset exit"
	@echo "...DONE"

# Debug: Start OpenOCD server only
debug-server: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "Starting OpenOCD server on port 3333..."
	$(OPENOCD_PATH) -s $(OPENOCD_INIT_PATH) \
		-f $(OPENOCD_IFACE_CFG) \
		-f $(OPENOCD_INIT_PATH)/k1921vg015.cfg \
		-c "gdb_port 3333" \
		-c "telnet_port 4444" \
		-c "tcl_port 6666" \
		-c "init" \
		-c "reset halt"

# Debug: Start GDB client
debug-gdb: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "Starting GDB session..."
	$(GDB) $(BUILD_PATH)/$(TARGET_NAME).elf \
		-ex "target extended-remote localhost:3333" \
		-ex "monitor reset halt" \
		-ex "load" \
		-ex "break main" \
		-ex "continue"

# Debug: Start both server and GDB (simplified)
debug: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "Starting debug session..."
	$(OPENOCD_PATH) -s $(OPENOCD_INIT_PATH) \
		-f $(OPENOCD_IFACE_CFG) \
		-f $(OPENOCD_INIT_PATH)/k1921vg015.cfg \
		-c "gdb_port 3333" \
		-c "telnet_port 4444" \
		-c "tcl_port 6666" \
		-c "init" \
		-c "reset halt" & \
	sleep 2 && \
	$(GDB) $(BUILD_PATH)/$(TARGET_NAME).elf \
		-ex "target extended-remote localhost:3333" \
		-ex "monitor reset halt" \
		-ex "load" \
		-ex "break main" \
		-ex "continue"

# Attach to a RUNNING target WITHOUT reset or reload — use this to catch a
# frozen/hung state. The .elf is only used for symbols, so it MUST match the
# image currently on the chip (don't rebuild between flashing and attaching).
attach: $(BUILD_PATH)/$(TARGET_NAME).elf
	@echo "Attaching to RUNNING target (no reset, no load)..."
	$(OPENOCD_PATH) -s $(OPENOCD_INIT_PATH) \
		-f $(OPENOCD_IFACE_CFG) \
		-f $(OPENOCD_INIT_PATH)/k1921vg015.cfg \
		-c "gdb_port 3333" \
		-c "telnet_port 4444" \
		-c "tcl_port 6666" \
		-c "init" \
		-c "halt" & \
	sleep 2 && \
	$(GDB) -nx $(BUILD_PATH)/$(TARGET_NAME).elf \
		-ex "set mem inaccessible-by-default off" \
		-ex "target extended-remote localhost:3333" \
		-ex "printf \"PC=0x%08x  mcause=0x%08x  mepc=0x%08x  mtval=0x%08x\\n\", \$$pc, \$$mcause, \$$mepc, \$$mtval" \
		-ex "backtrace"

help:
	@echo "Targets:"
	@echo "  make all          - build everything (COMPILER_PATH=... to override toolchain)"
	@echo "  make clean        - remove build artifacts"
	@echo "  make hex          - generate .hex file"
	@echo "  make size         - show memory usage"
	@echo "  make flash        - flash via OpenOCD (OPENOCD_PATH=... to override)"
	@echo "  make erase        - erase entire flash"
	@echo "  make debug        - start OpenOCD + GDB"
	@echo "  make debug-server - start OpenOCD server only"
	@echo "  make debug-gdb    - start GDB client only (server must already be running)"
	@echo "  make attach       - attach to a running target without reset/reload"
	@echo "  make help         - this help"
