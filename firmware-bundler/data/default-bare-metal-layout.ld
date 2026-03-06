
/* Licensed under the Apache-2.0 license. */

ENTRY(_start)

MEMORY
{
  ROM   (rx) : ORIGIN = ROM_START, LENGTH = ROM_LENGTH
  RAM  (rwx) : ORIGIN = RAM_START, LENGTH = RAM_LENGTH
}

SECTIONS
{
    .text :
    {
        _textstart = .;
        *(.text.init )
        *(.text*)
        *(.rodata*)
        _imem_end = .;
    } > RAM

    .stack (NOLOAD):
    {
        _ssram = .;
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

    .data :
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
        _kernel_ram_done = .;
    } > RAM

    _end = . ;
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
STACK_TOP = ADDR(.stack) + SIZEOF(.stack);
STACK_ORIGIN = ORIGIN(RAM);
MRAC_VALUE = 0xaaa9a5aa;
