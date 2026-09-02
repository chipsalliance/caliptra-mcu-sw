// Licensed under the Apache-2.0 license

//! `CM_MLKEM_KEY_GEN`, `CM_MLKEM_ENCAPSULATE` and `CM_MLKEM_DECAPSULATE` mailbox commands.
//!
//! These commands perform an ML-KEM key exchange through Caliptra:
//!
//! 1. [`mlkem_key_gen`] — generates an ML-KEM-1024 encapsulation key from a seed CMK.
//! 2. [`mlkem_encapsulate`] — performs encapsulation against the encapsulation key,
//!    producing ciphertext and a shared secret CMK.
//! 3. [`mlkem_decapsulate`] — performs decapsulation using the seed and ciphertext,
//!    recovering the shared secret CMK.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::wire::{
    mbox_execute, populate_checksum, CMD_CM_MLKEM_DECAPSULATE, CMD_CM_MLKEM_ENCAPSULATE,
    CMD_CM_MLKEM_KEY_GEN, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Size of the ML-KEM-1024 encapsulation key.
pub const CMB_MLKEM_ENCAPS_KEY_SIZE: usize = 1568;

/// Size of the ML-KEM-1024 ciphertext.
pub const CMB_MLKEM_CIPHERTEXT_SIZE: usize = 1568;
