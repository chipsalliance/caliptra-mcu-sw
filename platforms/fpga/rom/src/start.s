/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains startup code for bare-metal RISCV program

--*/

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


    # the FPGA does not clear RAM on reset, so we do it here
    li a0, 0x50000000
    li a1, 16384
    add a1, a1, a0
clear_dccm:
    sw zero, 0(a0)
    addi a0, a0, 4
    bltu a0, a1, clear_dccm

    li a0, 0xb0080000
    li a1, 393216
    add a1, a1, a0
clear_sram:
    sw zero, 0(a0)
    addi a0, a0, 4
    bltu a0, a1, clear_sram


    # Copy BSS
    la t0, BSS_START
    la t1, BSS_END
copy_bss:
    bge t0, t1, end_copy_bss
    sw x0, 0(t0)
    addi t0, t0, 4
    j copy_bss
end_copy_bss:

    # Copy data
    la t0, ROM_DATA_START
    la t1, DATA_START
    la t2, DATA_END
copy_data:
    bge t1, t2, end_copy_data
    lw t3, 0(t0)
    sw t3, 0(t1)
    addi t0, t0, 4
    addi t1, t1, 4
    j copy_data
end_copy_data:

    # call main entry point
    call main