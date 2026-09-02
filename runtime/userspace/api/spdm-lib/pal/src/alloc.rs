// Licensed under the Apache-2.0 license

//! MCU-side [`SpdmPalAlloc`] implementation.
//!
//! The underlying pool lives in
//! [`caliptra_mcu_scratch_alloc`](caliptra_mcu_scratch_alloc); this module
//! binds it to the SPDM stack by handing out [`ScratchBox`] / [`BitmapBytes`]
//! from the caller-supplied scratch region attached to [`McuSpdmPal`].

use super::measurements::MeasurementProvider;
use super::*;

impl<M: MeasurementProvider> SpdmPalAlloc for McuSpdmPal<M> {
    type Box<'a, T>
        = ScratchBox<'a, T>
    where
        Self: 'a,
        T: 'a;

    type Bytes<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    /// Allocates space for a `T` from the per-IO pool and moves
    /// `value` into it.
    ///
    /// # Parameters
    ///
    /// * `_io` — Ignored; the allocator is already scoped to the
    ///   current exchange (it is reset by `recv_request`).
    /// * `value` — The value moved into the freshly-reserved slots.
    ///
    /// # Returns
    ///
    /// * `Ok(ScratchBox<T>)` — RAII handle that derefs to `T` and
    ///   releases the slots on drop.
    /// * `Err(BAD_ALIGNMENT)` — `align_of::<T>()` exceeds
    ///   [`BITMAP_SLOT_SIZE`].
    /// * `Err(OUT_OF_MEMORY)` — no contiguous run of free slots of
    ///   the required size exists.
    fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>> {
        self.allocator.alloc(value)
    }

    /// Allocates a `len`-byte buffer from the per-IO pool.
    ///
    /// # Parameters
    ///
    /// * `_io` — Ignored; see [`Self::alloc`].
    /// * `len` — Requested buffer length in bytes. Rounded up to whole
    ///   slots internally.
    ///
    /// # Returns
    ///
    /// * `Ok(BitmapBytes)` — RAII handle that derefs to `[u8]` of
    ///   exactly `len` bytes (capacity may be larger).
    /// * `Err(OUT_OF_MEMORY)` — `len == 0`, `len > BitmapBytes::MAX_LEN`,
    ///   or no contiguous free run exists.
    fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>> {
        self.allocator.alloc_bytes(len)
    }

    fn large_buffered_msg_capacity(&self) -> usize {
        self.large_buffered_msg_capacity
    }

    type LargeBuf = BitmapBytes<'static>;

    fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
        self.allocator.alloc_bytes(len)
    }

    fn large_buf_into_bytes(
        &self,
        mut buf: Self::LargeBuf,
        len: usize,
    ) -> McuResult<Self::Bytes<'_>> {
        buf.shrink(len)?;
        Ok(buf)
    }

    type PersistentBox<T: Sized + 'static> = ScratchBox<'static, T>;

    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> McuResult<Self::PersistentBox<T>> {
        self.allocator.alloc(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use core::ptr::NonNull;

    /// Construct a fresh allocator over a heap-backed buffer for tests.
    fn make_alloc(capacity: usize) -> (BitmapAllocator, alloc::vec::Vec<u8>) {
        // Heap-backed buffer keeps the test target-independent. The Vec is
        // returned alongside so the caller can keep it alive for the
        // allocator's borrow.
        let mut buf = vec![0u8; capacity + BITMAP_SLOT_SIZE];
        // Round the base up to BITMAP_SLOT_SIZE alignment.
        let raw = buf.as_mut_ptr();
        let off = (raw as usize).wrapping_neg() & (BITMAP_SLOT_SIZE - 1);
        let ptr = unsafe { NonNull::new_unchecked(raw.add(off)) };
        let alloc = unsafe { BitmapAllocator::new(ptr, capacity) };
        (alloc, buf)
    }

    /// Validates the *shipping* emulator configuration: a 12 KiB pool must be
    /// able to hand out the declared 8 KiB buffered large-message allocation
    /// while the session working set is live, after sustained request churn.
    ///
    /// This is the empirical counterpart to the platform's `required_scratch()`
    /// build assertion. The assertion proves the arithmetic; this proves the
    /// allocator can actually place the run.
    ///
    /// Mirrors `platforms/emulator/.../spdm/mod.rs`:
    ///   * pool            = `SPDM_SCRATCH_SIZE`              = 12 KiB
    ///   * large buffer    = `MAX_BUFFERED_SPDM_MSG_SIZE`      =  8 KiB
    ///   * session set     = `SESSION_WORKING_SET`            = ~2.3 KiB live throughout
    ///   * inline response = `MAX_TRANSPORT_MTU`              =  1 KiB, concurrent with
    ///     the large buffer
    ///
    /// If this fails, either `SPDM_SCRATCH_SIZE` must grow or
    /// `MAX_BUFFERED_SPDM_MSG_SIZE` must shrink.
    #[test]
    fn buffered_large_message_capacity_is_allocatable_from_shipping_pool() {
        const POOL: usize = 12 * 1024;
        const MAX_BUFFERED_SPDM_MSG_SIZE: usize = 8 * 1024;
        const MAX_TRANSPORT_MTU: usize = 1024;

        let (alloc, _buf) = make_alloc(POOL);

        // Long-lived session working set: SessionInfo box (~1.3 KiB: nine
        // 128-byte CMKs plus the version string and sequence counters) and the
        // VCA / M1 / L1 / TH hash contexts (200 bytes each).
        let _session_info = alloc.alloc_bytes(1312).expect("session info alloc");
        let _vca = alloc.alloc_bytes(200).expect("vca alloc");
        let _m1 = alloc.alloc_bytes(200).expect("m1 alloc");
        let _l1 = alloc.alloc_bytes(200).expect("l1 alloc");
        let _th = alloc.alloc_bytes(200).expect("th alloc");

        let baseline_live = alloc.live_slots();

        // Sustained churn: alternate the crypto/certificate path and the
        // plain request path so the bitmap sees varied run sizes.
        for cycle in 0..50 {
            {
                let _recv = alloc
                    .alloc_bytes(MAX_TRANSPORT_MTU)
                    .unwrap_or_else(|_| panic!("recv alloc failed at cycle {}", cycle));
                let _mailbox = alloc
                    .alloc_bytes(2560)
                    .unwrap_or_else(|_| panic!("mailbox alloc failed at cycle {}", cycle));
                let _rsp_pt = alloc
                    .alloc_bytes(MAX_TRANSPORT_MTU)
                    .unwrap_or_else(|_| panic!("rsp plaintext alloc failed at cycle {}", cycle));
                let _rsp_ct = alloc
                    .alloc_bytes(MAX_TRANSPORT_MTU)
                    .unwrap_or_else(|_| panic!("rsp ciphertext alloc failed at cycle {}", cycle));
            }
            assert_eq!(
                alloc.live_slots(),
                baseline_live,
                "transient leak at cycle {}",
                cycle
            );
        }

        // The large-message path: inline response buffer and the rented large
        // buffer must coexist on top of the live session working set.
        let _inline = alloc
            .alloc_bytes(MAX_TRANSPORT_MTU)
            .expect("inline response buffer must fit alongside the session set");

        let largest_run_bytes = alloc.largest_free_run() * BITMAP_SLOT_SIZE;
        let large = alloc.alloc_bytes(MAX_BUFFERED_SPDM_MSG_SIZE);

        match large {
            Ok(buf) => assert_eq!(buf.len(), MAX_BUFFERED_SPDM_MSG_SIZE),
            Err(_) => panic!(
                "buffered large-message allocation is not deliverable: {} B allocation failed \
                 from a {} B pool after 50 cycles. baseline_live={} slots, \
                 largest_free_run={} bytes. Raise SPDM_SCRATCH_SIZE or lower \
                 MAX_BUFFERED_SPDM_MSG_SIZE in the platform SPDM config.",
                MAX_BUFFERED_SPDM_MSG_SIZE, POOL, baseline_live, largest_run_bytes
            ),
        }
    }
}
