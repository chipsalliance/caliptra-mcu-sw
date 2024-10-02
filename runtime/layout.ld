/* Licensed under the Apache-2.0 license. */

/* Based on the Tock board layouts, which are: */
/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

MEMORY
{
  rom (rx)  : ORIGIN = 0x00000000, LENGTH = 0x20000
  /* 128 bytes reserved for external interrupt table */
  ram (rwx) : ORIGIN = 0x50000080, LENGTH = 0x2ff80
  prog (rx) : ORIGIN = 0x00020000, LENGTH = 0x20000
}

INCLUDE runtime/kernel_layout.ld
