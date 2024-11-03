/* Licensed under the Apache-2.0 license. */

/* Based on the Tock board layouts, which are: */
/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

MEMORY
{
  /* 128 bytes reserved for external interrupt table */
  rom (rx)  : ORIGIN = 0x40000080, LENGTH = 0x1ff80 /* 128 kB - 80 bytes */
  prog (rx) : ORIGIN = 0x40020000, LENGTH = 0x20000 /* 128 kB*/
  ram (rwx) : ORIGIN = 0x50000000, LENGTH = 0x20000 /* 128 kB */
}

INCLUDE runtime/kernel_layout.ld
