
/* Licensed under the Apache-2.0 license. */

ENTRY(_start)

/*
 * The last 48 bytes of the ROM image are reserved for a SHA-384 digest that is
 * appended by the build step (see `append_rom_digest`). Carve them out of the
 * ROM region so the linker refuses to place code or rodata there.
 */
ROM_DIGEST_SIZE = 48;

/*
 * rom-from-ram: relocates caliptra-mcu-rom-common/romtime into SRAM
 * (RAM_TEXT, the last RAM_TEXT_SIZE bytes of SRAM) instead of executing them
 * from ROM; the platform adapter (platforms/emulator/rom/src) stays in ROM.
 *
 * .ram_text matches by input-section *name*, not archive/file: full LTO
 * (codegen-units = 1) erases per-crate object boundaries, but per-function
 * sections keep the v0-mangled crate name as a substring, so that still
 * routes each crate's surviving (non-inlined) functions to SRAM.
 *
 * Geometry here mirrors EMULATOR_MEMORY_MAP / MCU_ROM_RAM_TEXT_SIZE in
 * platforms/emulator/config/src/lib.rs -- keep both in sync by hand.
 */
SRAM_OFFSET = 0x40000000;
SRAM_SIZE = 0x100000;
RAM_TEXT_SIZE = 0x40000;
RAM_TEXT_ORIGIN = SRAM_OFFSET + SRAM_SIZE - RAM_TEXT_SIZE;

MEMORY
{
  ROM      (rx) : ORIGIN = ROM_START, LENGTH = ROM_LENGTH - ROM_DIGEST_SIZE
  RAM     (rwx) : ORIGIN = RAM_START, LENGTH = RAM_LENGTH /* dedicated SRAM for the ROM stack */
  RAM_TEXT(rwx) : ORIGIN = RAM_TEXT_ORIGIN, LENGTH = RAM_TEXT_SIZE
}

SECTIONS
{
    /* _start is the CPU reset vector; must be first in ROM. */
    .text.init :
    {
        *(.text.init)
        . = ALIGN(4);
    } > ROM

    /* Copied into SRAM by copy_ram_text() (riscv.rs). Symbols defined outside
       the section body so they still resolve if it ends up empty. */
    .ram_text : ALIGN(4)
    {
        /* explicitly `#[link_section = ".ram_text"]`-tagged items */
        *(.ram_text)
        *(.text.*caliptra_mcu_rom_common*)
        *(.text.*caliptra_mcu_romtime*)
        *(.rodata.*caliptra_mcu_rom_common*)
        *(.rodata.*caliptra_mcu_romtime*)
        . = ALIGN(4);
    } > RAM_TEXT AT> ROM

    ROM_RAM_TEXT_START = ADDR(.ram_text);
    ROM_RAM_TEXT_END = ADDR(.ram_text) + SIZEOF(.ram_text);
    ROM_RAM_TEXT_LOAD = LOADADDR(.ram_text);

    ASSERT(SIZEOF(.ram_text) <= RAM_TEXT_SIZE,
           "ROM .ram_text exceeds its reserved SRAM budget -- increase MCU_ROM_RAM_TEXT_SIZE (platforms/emulator/config) and RAM_TEXT_SIZE (this file), then adjust mcu_fw_sram_exec_region_size() to match")

    /* Everything else: remaining platform-adapter code and rodata. */
    .text :
    {
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > ROM

    ROM_DATA = .;

    .stack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + STACK_SIZE;
        . = ALIGN(4);
    } > RAM

    .estack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + ESTACK_SIZE;
        . = ALIGN(4);
        PROVIDE(ESTACK_START = . );
    } > RAM

    /DISCARD/ :
    {
        *(.eh_frame*)
    }

    .data : AT(ROM_DATA)
    {
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        . = ALIGN(4);
        PROVIDE( GLOBAL_POINTER = . + 0x800 );
        . = ALIGN(4);
    } > RAM

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
    } > RAM

    _end = . ;

    /DISCARD/ :
    {
        *(.eh_frame*)
    }
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_TOP = ORIGIN(RAM) + SIZEOF(.stack);
STACK_ORIGIN = ORIGIN(RAM);
