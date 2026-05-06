
/* Licensed under the Apache-2.0 license. */

ENTRY(_start)

MEMORY
{
  ROM   (rx) : ORIGIN = ROM_START, LENGTH = ROM_LENGTH
  RAM  (rwx) : ORIGIN = RAM_START, LENGTH = RAM_LENGTH /* dedicated SRAM for the ROM stack */
  HANDOFF (rw) : ORIGIN = HANDOFF_ADDR, LENGTH = HANDOFF_SIZE
}

SECTIONS
{

    .text :
    {
        *(.text.init )
        *(.text*)
        *(.rodata*)
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

    /* We reserve 1 KB at the end of DCCM for the handoff table.
       This must be 1KB aligned because the runtime requires DCCM regions
       to be 1KB aligned for MEIVT (Machine External Interrupt Vector Table). */
    .handoff (NOLOAD) :
    {
        KEEP(*(.handoff))
    } > HANDOFF

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
MRAC_VALUE = 0xaaa9a5aa;
