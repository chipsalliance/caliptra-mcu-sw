
/* Licensed under the Apache-2.0 license. */

ENTRY(_start)

MEMORY
{
  ROM   (rx) : ORIGIN = ROM_START, LENGTH = ROM_LENGTH
  RAM  (rwx) : ORIGIN = RAM_START, LENGTH = RAM_LENGTH /* dedicated SRAM for the ROM stack */
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

    .data : AT(ROM_DATA)
    {
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        KEEP(*(.eh_frame))
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

    .stack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + STACK_SIZE;
        . = ALIGN(4);
        PROVIDE(STACK_START = . );
    } > RAM

    .estack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + ESTACK_SIZE;
        . = ALIGN(4);
        PROVIDE(ESTACK_START = . );
    }

    _end = . ;
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_TOP = ORIGIN(RAM) + LENGTH(RAM);
STACK_ORIGIN = STACK_TOP - STACK_SIZE;
MRAC_VALUE = 0xaaa9a5aa;

