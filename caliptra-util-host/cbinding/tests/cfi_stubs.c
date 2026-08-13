// Licensed under the Apache-2.0 license

#include <stdint.h>
#include <stdlib.h>

void cfi_panic_handler(void) {
    abort();
}

volatile uint32_t CFI_STATE_ORG = 0;