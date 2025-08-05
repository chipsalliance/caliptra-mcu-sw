/*++

Licensed under the Apache-2.0 license.

File Name:

    cfi_stubs.c

Abstract:

    Stub implementations for Caliptra CFI (Control Flow Integrity) symbols
    that are not needed in the emulator C binding context.

--*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Stub for CFI panic handler
void cfi_panic_handler(void) {
    fprintf(stderr, "CFI panic handler called (stub implementation)\n");
    abort();
}

// Stub for CFI_STATE_ORG global variable
// This appears to be accessed as a pointer in the Rust code
volatile uint32_t CFI_STATE_ORG = 0;
