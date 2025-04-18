/* Licensed under the Apache-2.0 license */
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Tock Contributors 2023. */

/* Layout file for Tock process binaries that use libtock-rs. This currently
 * implements static linking, because we do not have a working
 * position-independent relocation solution. This layout works for all
 * platforms libtock-rs supports (ARM and RISC-V).
 *
 * This layout should be included by a script that defines the FLASH and RAM
 * regions for the board as well as TBF_HEADER_SIZE. Here is a an example
 * process binary linker script to get started:
 *
 *     TBF_HEADER_SIZE = 0x60;
 *
 *     FLASH_START = 0x10000;
 *     FLASH_LENGTH = 0x10000;
 *
 *     RAM_START = 0x20000;
 *     RAM_LENGTH = 0x10000;
 *
 *     INCLUDE ../libtock-rs/layout.ld
 *
 * FLASH refers to the area the process binary occupies in flash (including the
 * TBF headers, so FLASH_START refers to the TBF load address). RAM refers to
 * the area the process will have access to in memory. STACK_SIZE is the size of
 * the process' stack (this layout file may round the stack size up for
 * alignment purposes).
 *
 * This places the flash sections in the following order:
 *     1. .rt_header -- Constants used by runtime initialization.
 *     2. .text      -- Executable code.
 *     3. .rodata    -- Read-only global data (e.g. most string constants).
 *     4. .data      -- Read-write data, copied to RAM at runtime.
 *
 * This places the RAM sections in the following order:
 *     1. .stack -- The stack grows downward. Putting it first gives us
 *                  MPU-based overflow detection.
 *     2. .data  -- Read-write data, initialized by copying from flash.
 *     3. .bss   -- Zero-initialized read-write global data.
 *     4. Heap   -- The heap (optional) comes after .bss and grows upwards to
 *                  the process break.
 *
 * TBF_HEADER_SIZE is further used internally in the included `layout.ld` file
 * to set the `tbf_protected_region_size` symbol. elf2tab will thus prepend TBF
 * headers and an optional padding such that the final binary matches the
 * intended app load address (0x10000 in the above example).
 */

/* TODO: Should TBF_HEADER_SIZE be configured via a similar mechanism to the
 * stack size? We should see if that is possible.
 */

/* Rust's default linker (llvm-ld) as used with the Rust toolchain versions of
 * at least 2022-06-10, 2023-01-26, and 2023-06-27 can produce broken ELF
 * binaries when the RAM region's start address is not well-aligned to a 4kB
 * boundary. Unfortunately, this behavior is rather tricky to debug: instead of
 * refusing to produce a binary or producing a corrupt output, it generates an
 * ELF file which includes a segment that points to the ELF file's header
 * itself. elf2tab will include this segment in the final binary (as it is set
 * to be loaded), producing broken TBFs. This (overrideable) check is designed
 * to warn users that the linker may be misbehaved under these conditions.
 */
PROVIDE(LIBTOCKRS_OVERRIDE_RAM_ORIGIN_CHECK = 0);
ASSERT(LIBTOCKRS_OVERRIDE_RAM_ORIGIN_CHECK == 1 || RAM_START % 0x1000 == 0, "
Start of RAM region must be well-aligned to a 4kB boundary for LLVM's lld to
work. Refer to https://github.com/tock/libtock-rs/pull/477 for more
information. Set LIBTOCKRS_OVERRIDE_RAM_ORIGIN_CHECK = 1 to override this check
(e.g., when using a different linker).");

MEMORY {
  FLASH (X) : ORIGIN = FLASH_START + TBF_HEADER_SIZE, LENGTH = FLASH_LENGTH - TBF_HEADER_SIZE
  RAM   (W) : ORIGIN = RAM_START                    , LENGTH = RAM_LENGTH
}

/* GNU LD looks for `start` as an entry point by default, while LLVM's LLD looks
 * for `_start`. To be compatible with both, we manually specify an entry point.
 */
ENTRY(start)

SECTIONS {
    /* The FLASH memory section is placed at a TBF_HEADER_SIZE offset, to give
     * elf2tab room to prepend the TBF headers. Communicate this reservation to
     * elf2tab, such that it fills up the space after the TBF headers (if any)
     * as part of the protected region trailer:
     */
    tbf_protected_region_size = TBF_HEADER_SIZE;

    /* Sections located in FLASH at runtime.
     */

    /* Runtime header. Contains values the linker knows that the runtime needs
     * to look up.
     */
    . = ALIGN(4);
    .start : {
        /* We combine rt_header and _start into a single section. If we don't,
         * elf2tab does not parse the ELF file correctly for unknown reasons.
         */
        rt_header = .;
        LONG(start & 0xFFFFFFFE);        /* .start w/ Thumb bit unset */
        LONG(ADDR(.bss) + SIZEOF(.bss)); /* Initial process break */
        LONG(_stack_top);
        LONG(SIZEOF(.data));
        LONG(LOADADDR(.data));
        LONG(ADDR(.data));
        LONG(SIZEOF(.bss));
        LONG(ADDR(.bss));

        *(.start)
    } > FLASH

    /* Text section -- the application's code. */
    .text ALIGN(4) : {
        *(.text.*)
    } > FLASH

    /* Read-only data section. Contains strings and other global constants. */
    .rodata ALIGN(4) : {
        *(.rodata.*)

        /* Generated by GCC in libraries for variables that still have relocations but are constant
         * at runtime. See https://www.airs.com/blog/archives/189 for background.
         */
        *(.data.rel.ro.*)
    } > FLASH

    /* Sections located in RAM at runtime.
     */

    /* Reserve space for the stack. Aligned to a multiple of 16 bytes for the
     * RISC-V calling convention:
     * https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf
     */
    .stack (NOLOAD) : {
	/* _sram_origin is used by elf2tab:
	 * https://github.com/tock/elf2tab/blob/master/src/main.rs#L301
	 */
        _sram_origin = .;
        KEEP(*(.stack_buffer))
        . = ALIGN(16);
        _stack_top = .;  /* Used in rt_header */
    } > RAM AT > FLASH

    /* Read-write data section. This is deployed as part of FLASH but is copied
     * into RAM at runtime.
     */
    .data ALIGN(4) : {
        data_ram_start = .;
        /* .sdata is the RISC-V small data section */
        *(.sdata .data*)
        /* Pad to word alignment so the relocation loop can use word-sized
         * copies.
         */
        . = ALIGN(4);
    } > RAM AT > FLASH

    /* BSS section. These are zero-initialized static variables. This section is
     * not copied from FLASH into RAM but rather directly initialized, and is
     * mainly put in this linker script so that we get an error if it overflows
     * the RAM region.
     */
    .bss ALIGN(4) (NOLOAD) : {
        /* .sbss is the RISC-V small data section */
        *(.sbss .bss.*)
    } > RAM AT > FLASH

    _heap_start = ADDR(.bss) + SIZEOF(.bss);  /* Used by rt_header */

    /* Sections we do not need. */
    /DISCARD/ :
    {
      *(.ARM.exidx .eh_frame)
    }
}

/* Check that the linker thinks our start of flash is page aligned. Now, the
 * linker doesn't actually know the size of pages, and for our purposes we don't
 * necessarily care that these are aligned, but the linker will generate
 * segments which are aligned to what it thinks the page size is. This will
 * cause the linker to insert segments _before_ `FLASH_START`, which is not what
 * we intend. To ensure more valid-looking .elf files, we check that
 * `FLASH_START` is aligned to what the linker thinks is the page size.
 *
 * If this check fails, it is likely the linker is using a page size of 0x10000
 * (based on observations in Aug 2023). The linker argument `-z
 * max-page-size=4096` changes this setting. We recommend adding
 * `println!("cargo:rustc-link-arg=-zmax-page-size=4096");` to your build.rs
 * file to fix this issue.
 */
ASSERT(FLASH_START % CONSTANT(MAXPAGESIZE)==0, "
FLASH_START not page aligned according to the linker.
This will cause issues with generated .elf segments.
The linker is probably assuming too large of a page size.
Add `println!('cargo:rustc-link-arg=-zmax-page-size=4096');` to build.rs to fix.")
