// Licensed under the Apache-2.0 license

//! [`SpdmPalHash`] + [`ApiAlloc`] implementations on [`McuSpdmPal`].
//!
//! The file is named `hash.rs` mirroring
//! [`mcu_spdm_lite_traits::SpdmPalHash`] in
//! [`traits/src/hash.rs`](../../traits/src/hash.rs). The
//! [`ApiAlloc`] binding lives here as well because it shares the
//! same dependency on the pool allocator that backs every hash
//! request.

use super::*;
use mcu_caliptra_api_lite::{sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, HashState};
use mcu_spdm_lite_traits::{SpdmPalHash, SpdmPalHashAlgo, SpdmPalIo};

impl ApiAlloc for McuSpdmPal {
    type Buf<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    #[inline]
    fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
        self.allocator.alloc_bytes(len)
    }
}

impl SpdmPalHash for McuSpdmPal {
    type State = HashState;

    #[inline]
    async fn hash_init(
        &self,
        _io: &impl SpdmPalIo,
        algo: SpdmPalHashAlgo,
        seed: &[u8],
    ) -> McuResult<HashState> {
        sha_init(self, to_api_algo(algo), seed).await
    }

    #[inline]
    async fn hash_update(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut HashState,
        data: &[u8],
    ) -> McuResult<()> {
        sha_update(self, state, data).await
    }

    #[inline]
    async fn hash_finish(
        &self,
        _io: &impl SpdmPalIo,
        state: &mut HashState,
        out: &mut [u8],
    ) -> McuResult<()> {
        sha_finish(self, state, out).await
    }
}

/// Map the SPDM-protocol algorithm selector onto the
/// Caliptra-mailbox algorithm code.
#[inline]
fn to_api_algo(algo: SpdmPalHashAlgo) -> HashAlgo {
    match algo {
        SpdmPalHashAlgo::Sha384 => HashAlgo::Sha384,
    }
}
