// Licensed under the Apache-2.0 license.

.option norvc

.section .text.init
.global _start
_start:

.option push
.option norelax
    la gp, GLOBAL_POINTER
.option pop

    # Initialize the stack pointer
    la sp, STACK_TOP

    # Copy BSS
    la t0, BSS_START
    la t1, BSS_END
copy_bss:
    bge t0, t1, end_copy_bss
    sw x0, 0(t0)
    addi t0, t0, 4
    j copy_bss
end_copy_bss:

    # In bare-metal-runtime, we are running entirely from RAM (LMA=VMA).
    # Data is already where it needs to be, so no need to copy from ROM to RAM.

    # call main entry point
    call main

    # exit the emulator
    la t0, EMU_CTRL_EXIT
    sw zero, 0(t0)

.section .data
.equ  EMU_CTRL_EXIT, 0x10002000
