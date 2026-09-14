/** @file
*  @brief linker script for K1921VG015: project in Flash
*/

OUTPUT_ARCH( "riscv" )
ENTRY(_start)

/* ROM ORIGIN/LENGTH switch on whether this build is meant to be chain-loaded
 * by wolfBoot or run standalone from raw flash 0. Controlled by a linker
 * symbol, not a Makefile-side .ld swap, so both variants stay generated from
 * this one file:
 *   - default (WOLFBOOT_ENABLED undefined): ORIGIN=0x80000000, LENGTH=896K —
 *     unchanged standalone behavior, flash/boot this .elf directly, no
 *     bootloader involved. This is `make`'s default (WOLFBOOT=0).
 *   - `make WOLFBOOT=1` (LDFLAGS gets -Wl,--defsym=WOLFBOOT_ENABLED=1):
 *     ORIGIN = WOLFBOOT_PARTITION_BOOT_ADDRESS (0x80010000) + IMAGE_HEADER_SIZE
 *     (0x100); LENGTH = WOLFBOOT_PARTITION_SIZE (0x60000, 384K, see
 *     sovaSecureBoot/.config) minus that same header. wolfBoot always jumps
 *     to PART_BOOT_ADDRESS+IMAGE_HEADER_SIZE regardless of this firmware's
 *     own entry symbol, so whatever lands at ORIGIN here IS the boot entry
 *     point when chain-loaded.
 * ROM_DATA is untouched either way — storageManager's persistent device/
 * session/identity tables stay at their fixed offset, independent of which
 * mode is active, and the wolfBoot BOOT+UPDATE+swap footprint
 * (0x80010000-0x800D1000) stays well clear of it regardless. */
MEMORY {
  ROM      (rwx) : ORIGIN = DEFINED(WOLFBOOT_ENABLED) ? 0x80010100 : 0x80000000,
                    LENGTH = DEFINED(WOLFBOOT_ENABLED) ? 0x5FF00    : 896K
  ROM_DATA (rw)  : ORIGIN = 0x800E0000, LENGTH = 128K
  RAM0     (rwx) : ORIGIN = 0x40000000, LENGTH = 256K
  RAM1     (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
}

REGION_ALIAS("REGION_TEXT",   ROM );
REGION_ALIAS("REGION_RODATA", ROM );
REGION_ALIAS("REGION_DATA",   RAM0);
REGION_ALIAS("REGION_BSS",    RAM0);
REGION_ALIAS("REGION_STACK",  RAM0);

STACK_SIZE = 2048;

/*
*  @brief Common part of bare metal linker script
*/

/*
*  Some external definitions are requeued:
* - output format, arch and entry point (OUTPUT_FORMAT, OUTPUT_ARCH, ENTRY commands)
* - memory layout (MEMORY command)
* - memory regions' aliases (REGION_ALIAS comand)
* - stack size (STACK_SIZE symbol, i.e. "STACK_SIZE = 2048;")
* - size of heap ("HEAP_FIXED_AFTER_BSS=<size>", default it is a space between end of .bss and start of .stack)
*/

STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : 2048;

SECTIONS {
  /* startup/crt code segment */
  .text.startup ORIGIN(REGION_TEXT) : {
    *(.startup.entry .startup.*)
    . = ALIGN(16);
    *(.init.rodata .init.rodata.*)
    . = ALIGN(16);
    *(.init.data .init.data.*)
    . = ALIGN(16);
    *(.init.text .init.text.*)
    . = ALIGN(16);
  } >REGION_TEXT

  __TEXT_INIT_START__ = LOADADDR(.text.startup);
  __TEXT_INIT_SIZE__ = SIZEOF(.text.startup);

  .text.crt : ALIGN(16) {
    *(.text.crt*)
  } >REGION_TEXT

  /* code segment */
  .text : ALIGN(4) {
    PROVIDE(__TEXT_START__ = .);
    *(.text .text.*)
    PROVIDE(__TEXT_END__ = .);
  } >REGION_TEXT
  
  .init_array : ALIGN(4) {
     KEEP(*(SORT(.init_array*)))
  } >REGION_DATA AT>REGION_TEXT
  
  .fini_array : ALIGN(4) {
     KEEP(*(SORT(.fini_array*)))
  } >REGION_DATA AT>REGION_TEXT

  /* thread-local data segment */
  .tdata : ALIGN(4) {
    PROVIDE(_tls_data = .);
    PROVIDE(_tdata_start = .);
    *(.tdata .tdata.*)
    PROVIDE(_tdata_end = .);
  } >REGION_RODATA

  .tbss : ALIGN(4) {
    PROVIDE(_tbss_start = .);
    *(.tbss .tbss.*)
    . = ALIGN(4);
    PROVIDE(_tbss_end = .);
  } >REGION_RODATA

  __TLS_SIZE__ = (_tbss_end - _tdata_start + 0xf) & ~0xf;

  /* read-only data segment */
  .rodata : ALIGN(4) {
    *(.rodata) *(.rodata.*) *(.gnu.linkonce.r.*)
  } >REGION_RODATA

  /* small read-only data segment */
  .srodata : {
    *(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2) *(.srodata*)
  } >REGION_RODATA

  /* small data segment */
  .sdata : ALIGN(4) {
    __SDATA_BEGIN__ = .;
    *(.sdata .sdata.* .sdata2.* .gnu.linkonce.s.*)
  } >REGION_DATA AT>REGION_TEXT

  /* data segment */
  .data : ALIGN(4) {
    __DATA_BEGIN__ = .;
    *(.data .data.* .gnu.linkonce.d.*)
    _edata = .; PROVIDE (edata = .);
  } >REGION_DATA AT>REGION_TEXT
  
  PROVIDE( __data_source_start = LOADADDR(.data) );
  PROVIDE( __data_target_start = ADDR(.data) );
  PROVIDE( __data_target_end = ADDR(.data) + SIZEOF(.data) );
  
  PROVIDE( __sdata_source_start = LOADADDR(.sdata) );
  PROVIDE( __sdata_target_start = ADDR(.sdata) );
  PROVIDE( __sdata_target_end = ADDR(.sdata) + SIZEOF(.sdata) );
  
  PROVIDE( __init_array_source_start = LOADADDR(.init_array) );
  PROVIDE( __init_array_target_start = ADDR(.init_array) );
  PROVIDE( __init_array_target_end = ADDR(.init_array) + SIZEOF(.init_array) );
  
  PROVIDE( __fini_array_source_start = LOADADDR(.fini_array) );
  PROVIDE( __fini_array_target_start = ADDR(.fini_array) );
  PROVIDE( __fini_array_target_end = ADDR(.fini_array) + SIZEOF(.fini_array) );

  /* bss segment
   *
   * AT>REGION_TEXT here matters even though .bss/.sbss carry no file
   * content: without an explicit load address, their LMA defaults to
   * matching their RAM VMA (0x40000000+), and objcopy -O binary lays out
   * a flat .bin by LMA — bridging the full RAM<->FLASH address distance
   * (~1GB) with fill bytes if nothing pins it near the actual code. This
   * was never hit before because SovaHub has only ever been flashed as a
   * .elf directly (OpenOCD honors each segment's own load address natively
   * there); a flat .bin for wolfBoot's bin-assemble pipeline needs it. */
  .sbss : {
    PROVIDE(__bss_start = .);
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.scommon)
  } >REGION_BSS AT>REGION_TEXT

  .bss : ALIGN(4) {
    *(.bss .bss.* .gnu.linkonce.b.*)
    *(COMMON)
    . = ALIGN(4);
    __BSS_END__ = .;
    PROVIDE(__bss_end = .);
    PROVIDE(_end = .);
    PROVIDE(__end = .);
     /* for libc nano */
        end = .;
    /*    _end = .; */
        _ebss = .;
  } >REGION_BSS AT>REGION_TEXT

  /* End of uninitalized data segement */

  __global_pointer$ = MIN(__DATA_BEGIN__ + 0x780,
                          MAX(__SDATA_BEGIN__ + 0x780, __BSS_END__ - 0x780));

  /* Stack segement */
  .stack ORIGIN(REGION_STACK) + LENGTH(REGION_STACK) - STACK_SIZE - __TLS_SIZE__ : {
    PROVIDE(__STACK_START__ = .);
    . += STACK_SIZE;
    PROVIDE(__C_STACK_TOP__ = .);
    PROVIDE(__STACK_END__ = .);
    PROVIDE(__TLS0_BASE__ = .);
  } >REGION_STACK

  _heap_start = ALIGN(__bss_end, 16);
  _heap_end   = DEFINED(HEAP_FIXED_AFTER_BSS) ? MIN(ALIGN(__STACK_START__, 16), (_heap_start + HEAP_FIXED_AFTER_BSS)) : ALIGN(__STACK_START__, 16);
 
  /* discard relocation code */
  /* plf_init_relocate = plf_init_noreloc;*/

  /*
   * ROM_DATA persistent storage — not erased by OTA (firmware targets ROM only).
   * These sections are NOLOAD so the startup code does not try to copy them.
   * storageManager reads/writes them directly via flash HAL registers.
   */
  .sm_device_table (NOLOAD) : ALIGN(4096) {
    __sm_device_table_start__ = .;
    . += 16K;
    __sm_device_table_end__ = .;
  } >ROM_DATA

  .sm_session_table (NOLOAD) : ALIGN(4096) {
    __sm_session_table_start__ = .;
    . += 16K;
    __sm_session_table_end__ = .;
  } >ROM_DATA

  .sm_hub_identity (NOLOAD) : ALIGN(4096) {
    __sm_hub_identity_start__ = .;
    . += 4K;
    __sm_hub_identity_end__ = .;
  } >ROM_DATA

  /*
   * RAM1 (VBAT/battery domain, 0x10000000, 64K) — retained across a warm
   * reset (WDT-triggered, see platform/include/wdt_reset.h) and, hardware
   * permitting, a full power loss if this board populates a VBAT source
   * (unconfirmed at the board level). NOLOAD: startup code must not zero
   * these — a warm reset should find the previous boot's live data still
   * here. Canary-guarded (magic+size+crc32, see platform/include/
   * ram1_canary.h) — never trust without validating first; on a true cold
   * boot (or a firmware update that changed the payload's layout) this is
   * indistinguishable from garbage and must be treated as such.
   *
   * Unlike the ROM_DATA sections above, no byte budget is reserved by hand
   * here — RAM1 is ordinary (rwx) SRAM, not flash behind a HAL, so C code
   * places statically-sized structs into these sections by name
   * (__attribute__((section(...)))) and the linker's own "region RAM1
   * overflowed" error is the size guard, which stays correct as those
   * structs grow instead of silently going stale like a hand-picked
   * constant would.
   */
  .ram1_device_table (NOLOAD) : ALIGN(4) {
    *(.ram1_device_table)
  } >RAM1

  .ram1_radio_sessions (NOLOAD) : ALIGN(4) {
    *(.ram1_radio_sessions)
  } >RAM1

  .ram1_boot_reason (NOLOAD) : ALIGN(4) {
    *(.ram1_boot_reason)
  } >RAM1

  /DISCARD/ : {
    *(.init.text.plf_init_relocate)
    *(.eh_frame .eh_frame.*)
  }
}

