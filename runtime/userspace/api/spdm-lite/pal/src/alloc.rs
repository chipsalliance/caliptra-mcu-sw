// Licensed under the Apache-2.0 license

//! MCU-side [`SpdmPalAlloc`] implementation plus the underlying
//! [`BitmapAllocator`].
//!
//! The allocator is a single-task, `Box`-like, bitmap-managed pool over a
//! caller-supplied buffer. It hands out two kinds of RAII owners:
//!
//! * [`McuSpdmBox<T>`] — owns a `T` in a contiguous run of slots; drops the
//!   value in place and releases the slots on `Drop`.
//! * [`BitmapBytes`] — owns a `[u8]` view over one or more slots; can be
//!   shrunk in place via [`BitmapBytes::shrink`] to release trailing slots
//!   (used by receive paths that allocate `mtu()` and trim to the real
//!   message length).
//!
//! The allocator serves both per-request scratch allocations and any
//! connection-scoped large-message buffer parked on `ConnectionState`.
//!
//! # Soundness
//!
//! [`BitmapAllocator`] is `!Send` + `!Sync`; the bitmap is mutated through
//! [`UnsafeCell`] and assumes a single-threaded SPDM responder. Calling its
//! methods concurrently is undefined behavior.

use super::measurements::MeasurementProvider;
use super::*;
use core::cell::Cell;

impl<M: MeasurementProvider> SpdmPalAlloc for McuSpdmPal<M> {
    type Box<'a, T>
        = McuSpdmBox<'a, T>
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
    /// * `Ok(McuSpdmBox<T>)` — RAII handle that derefs to `T` and
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

    fn large_capacity(&self) -> usize {
        self.allocator.largest_free_run() * crate::BITMAP_SLOT_SIZE
    }

    type LargeBuf = BitmapBytes<'static>;

    fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
        self.allocator.alloc_bytes(len)
    }

    type PersistentBox<T: Sized + 'static> = McuSpdmBox<'static, T>;

    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> McuResult<Self::PersistentBox<T>> {
        self.allocator.alloc(value)
    }
}

// ---------------------------------------------------------------------------
// Bitmap allocator
// ---------------------------------------------------------------------------
//
// A single-threaded `Box`-like bitmap allocator backed by a caller-supplied
// memory region. The beginning of the region holds the slot-occupancy bitmap;
// the remainder is split into fixed-size slots.
//
// Layout of the buffer pointed to by `ptr`:
//
//     +------------------+----- aligned to SLOT_SIZE -----+--------------+
//     | bitmap (1 bit/slot, ceil(N/8) bytes, zeroed)      | slot 0 ... N |
//     +---------------------------------------------------+--------------+
//
// `alloc::<T>(v)` finds a contiguous run of `ceil(size_of::<T>() / SLOT_SIZE)`
// free slots, marks them used, moves `v` in, and returns a `McuSpdmBox<T>`
// that derefs to the value and releases the slots back to the bitmap on drop
// — the same lifecycle as `alloc::boxed::Box`, but on a fixed pool.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::{align_of, size_of, MaybeUninit};
use core::ptr::NonNull;

/// Slot granularity in bytes. Each bit in the occupancy bitmap tracks one
/// slot of this size, so every allocation is rounded up to a multiple of
/// `BITMAP_SLOT_SIZE`.
///
/// 64 bytes was chosen to comfortably hold the SPDM common header plus
/// every fixed-size body the responder currently emits while keeping the
/// bitmap small (1 bit per 64 bytes ≈ 0.2 % overhead).
pub const BITMAP_SLOT_SIZE: usize = 64;

use mcu_error::codes::{BAD_ALIGNMENT as ERR_BAD_ALIGNMENT, OUT_OF_MEMORY as ERR_OUT_OF_MEMORY};

/// Single-threaded bitmap allocator over a caller-supplied buffer.
///
/// The buffer's first `ceil(num_slots / 8)` bytes (rounded up to
/// `BITMAP_SLOT_SIZE`) are used as the occupancy bitmap; the rest is carved
/// into `BITMAP_SLOT_SIZE`-byte slots. The bitmap itself is mutated through
/// an [`UnsafeCell`] — sound only because the type is `!Sync` and the
/// containing context is used from a single executor task.
pub struct BitmapAllocator {
    /// Base of the caller-supplied buffer.
    base: NonNull<u8>,
    /// First slot byte (bitmap end, rounded up to `BITMAP_SLOT_SIZE`).
    data: NonNull<u8>,
    /// Number of slots managed by the bitmap.
    num_slots: usize,
    /// Running count of slots currently marked live (incremented by
    /// `alloc_run`, decremented by `free_run`). Maintained for cheap
    /// `live_slots()` and as the running input to `max_live_slots`.
    live_count: Cell<u32>,
    /// High-water mark of `live_count` over the allocator's lifetime.
    /// Updated on every `alloc_run`. Read via `max_live_slots()`.
    max_live: Cell<u32>,
    /// Interior mutability marker; the actual bitmap storage lives in the buffer.
    _state: UnsafeCell<()>,
    /// `!Send` + `!Sync` marker.
    _not_send: PhantomData<*mut ()>,
}

impl BitmapAllocator {
    /// Constructs a new bitmap allocator over `[ptr, ptr + capacity)`.
    ///
    /// The buffer is split into:
    ///
    /// 1. A zeroed occupancy bitmap (`ceil(num_slots / 8)` bytes, padded
    ///    up to a multiple of [`BITMAP_SLOT_SIZE`]).
    /// 2. `num_slots` data slots of [`BITMAP_SLOT_SIZE`] bytes each.
    ///
    /// `num_slots` is chosen to maximise total slot count while keeping
    /// `bitmap + slots <= capacity`.
    ///
    /// # Parameters
    ///
    /// * `ptr` — Base of the caller-supplied buffer.
    /// * `capacity` — Total length, in bytes, of the buffer at `ptr`.
    ///
    /// # Returns
    ///
    /// A new `BitmapAllocator` with an empty (zeroed) bitmap. If
    /// `capacity` is too small to fit even one slot plus its bitmap byte,
    /// `num_slots` is 0 and every allocation will fail with
    /// `OUT_OF_MEMORY`.
    ///
    /// # Safety
    ///
    /// * `ptr` must be non-null, aligned to [`BITMAP_SLOT_SIZE`], and point
    ///   to `capacity` bytes of writable memory that is exclusively owned
    ///   by the returned allocator for its entire lifetime.
    /// * The memory must outlive every [`McuSpdmBox`] / [`BitmapBytes`]
    ///   handed out by this allocator.
    /// * The allocator must not be moved across threads (it is `!Send`).
    pub unsafe fn new(ptr: NonNull<u8>, capacity: usize) -> Self {
        // Solve for the largest `num_slots` such that:
        //     align_up(ceil(num_slots / 8), SLOT_SIZE) + num_slots * SLOT_SIZE <= capacity
        let slot_bits = BITMAP_SLOT_SIZE * 8;
        let mut num_slots = (capacity * 8) / (slot_bits + 1);
        loop {
            let bm_bytes = num_slots.div_ceil(8);
            let bm_aligned = (bm_bytes + BITMAP_SLOT_SIZE - 1) & !(BITMAP_SLOT_SIZE - 1);
            if bm_aligned + num_slots * BITMAP_SLOT_SIZE <= capacity {
                break;
            }
            if num_slots == 0 {
                break;
            }
            num_slots -= 1;
        }

        let bm_bytes = num_slots.div_ceil(8);
        let bm_aligned = (bm_bytes + BITMAP_SLOT_SIZE - 1) & !(BITMAP_SLOT_SIZE - 1);

        // Zero the bitmap; the data region is left uninitialized.
        core::ptr::write_bytes(ptr.as_ptr(), 0, bm_bytes);

        let data = NonNull::new_unchecked(ptr.as_ptr().add(bm_aligned));
        Self {
            base: ptr,
            data,
            num_slots,
            live_count: Cell::new(0),
            max_live: Cell::new(0),
            _state: UnsafeCell::new(()),
            _not_send: PhantomData,
        }
    }

    /// Returns the number of slots managed by this allocator.
    ///
    /// # Returns
    ///
    /// The total slot count fixed at construction time — the maximum
    /// number of single-slot allocations that can be live at once.
    pub fn num_slots(&self) -> usize {
        self.num_slots
    }

    /// Returns the number of slots currently marked live (the running
    /// count maintained by [`Self::alloc_run`] and [`Self::free_run`]).
    ///
    /// A correctly-functioning steady-state responder returns to a known
    /// baseline (zero, or the count of slots held by persistent allocations
    /// owned by `ConnectionState`) between SPDM requests. A drift above the
    /// baseline points at a leaked [`BitmapBytes`] / [`McuSpdmBox`] handle.
    pub fn live_slots(&self) -> usize {
        self.live_count.get() as usize
    }

    /// Returns the highest value [`Self::live_slots`] has reached since
    /// allocator construction. Updated on every [`Self::alloc_run`].
    ///
    /// Useful for sizing the scratch region against observed peaks.
    pub fn max_live_slots(&self) -> usize {
        self.max_live.get() as usize
    }

    /// Returns the largest contiguous run of currently-free slots, in
    /// slot units. O(num_slots) scan — intended for diagnostics, not
    /// the hot path.
    ///
    /// Useful for spotting fragmentation: `live_slots() + largest_free_run()`
    /// can be less than `num_slots()` when free space is split across the
    /// bitmap.
    pub fn largest_free_run(&self) -> usize {
        let mut best = 0usize;
        let mut run = 0usize;
        for i in 0..self.num_slots {
            if self.bit(i) {
                if run > best {
                    best = run;
                }
                run = 0;
            } else {
                run += 1;
            }
        }
        if run > best {
            best = run;
        }
        best
    }

    /// Resets the allocator by clearing every bit in the occupancy bitmap.
    ///
    /// Used by [`McuSpdmPal::recv_request`] to scope all allocations to a
    /// single SPDM exchange. After reset, the slot region's bytes are
    /// *not* zeroed — they remain whatever the previous owner left there.
    ///
    /// # Safety
    ///
    /// All outstanding [`McuSpdmBox`] / [`BitmapBytes`] handles created
    /// from this allocator must have been dropped before calling this.
    /// Resetting while a handle is live would mean the next allocation
    /// could alias an existing borrow — undefined behavior.
    pub unsafe fn reset(&self) {
        let bm_bytes = self.num_slots.div_ceil(8);
        core::ptr::write_bytes(self.base.as_ptr(), 0, bm_bytes);
        self.live_count.set(0);
    }

    /// Allocates a byte buffer of `len` bytes from the pool.
    ///
    /// Internally the allocation is rounded up to whole slots; the
    /// returned [`BitmapBytes`] can be shrunk via
    /// [`BitmapBytes::shrink`] to release trailing slots back to the
    /// pool — useful for receive paths that allocate the transport MTU
    /// then trim to the real message length.
    ///
    /// # Parameters
    ///
    /// * `len` — Logical length in bytes. Capacity will be
    ///   `ceil(len / BITMAP_SLOT_SIZE) * BITMAP_SLOT_SIZE`.
    ///
    /// # Returns
    ///
    /// * `Ok(BitmapBytes)` — Owning handle whose `len()` equals `len`.
    ///
    /// # Errors
    ///
    /// * `OUT_OF_MEMORY` — `len == 0`, `len` exceeds
    ///   [`BitmapBytes::MAX_LEN`], the required slot count exceeds
    ///   [`BitmapBytes::MAX_SLOTS`], or no contiguous run of free slots
    ///   of the required size exists.
    pub fn alloc_bytes(&self, len: usize) -> McuResult<BitmapBytes<'_>> {
        if len == 0 || len > BitmapBytes::MAX_LEN {
            return Err(ERR_OUT_OF_MEMORY);
        }
        let n = len.div_ceil(BITMAP_SLOT_SIZE);
        if n > BitmapBytes::MAX_SLOTS {
            return Err(ERR_OUT_OF_MEMORY);
        }
        let start = self.alloc_run(n).ok_or(ERR_OUT_OF_MEMORY)?;
        let unused = (n * BITMAP_SLOT_SIZE - len) as u8;
        Ok(BitmapBytes {
            alloc: self,
            start_slot: start as u16,
            slots_tail: BitmapBytes::pack(n as u16, unused),
        })
    }

    /// Allocates space for a `T`, moves `value` in, and returns an
    /// owning [`McuSpdmBox`].
    ///
    /// # Parameters
    ///
    /// * `value` — The value moved into the reserved slots.
    ///
    /// # Returns
    ///
    /// * `Ok(McuSpdmBox<T>)` — RAII owner; drops the value in place and
    ///   releases the slots on `Drop`.
    ///
    /// # Errors
    ///
    /// * `BAD_ALIGNMENT` — `align_of::<T>()` exceeds [`BITMAP_SLOT_SIZE`].
    /// * `OUT_OF_MEMORY` — required slot count exceeds `u16::MAX`, or
    ///   no contiguous run of free slots of the required size exists.
    pub fn alloc<T>(&self, value: T) -> McuResult<McuSpdmBox<'_, T>> {
        if align_of::<T>() > BITMAP_SLOT_SIZE {
            return Err(ERR_BAD_ALIGNMENT);
        }
        let n = size_of::<T>().div_ceil(BITMAP_SLOT_SIZE).max(1);
        if n > u16::MAX as usize {
            return Err(ERR_OUT_OF_MEMORY);
        }
        let start = self.alloc_run_backwards(n).ok_or(ERR_OUT_OF_MEMORY)?;

        // SAFETY: `start..start+n` slots are now marked used (exclusive
        // ownership), within bounds, and properly aligned for `T`.
        unsafe {
            let p = self.data.as_ptr().add(start * BITMAP_SLOT_SIZE) as *mut T;
            core::ptr::write(p, value);
            Ok(McuSpdmBox {
                alloc: self,
                start_slot: start as u16,
                num_slots: n as u16,
                _marker: PhantomData,
            })
        }
    }

    /// Computes the typed pointer for a slot index.
    ///
    /// # Parameters
    ///
    /// * `start_slot` — Slot index returned by [`Self::alloc_run`].
    ///
    /// # Returns
    ///
    /// A non-null pointer to `data + start_slot * BITMAP_SLOT_SIZE`.
    /// The caller is responsible for ensuring the slot is initialized
    /// and exclusively owned.
    #[inline]
    fn slot_ptr<T>(&self, start_slot: u16) -> NonNull<T> {
        // SAFETY: `start_slot` was produced by `alloc_run` so it is < num_slots.
        unsafe {
            NonNull::new_unchecked(
                self.data
                    .as_ptr()
                    .add(start_slot as usize * BITMAP_SLOT_SIZE) as *mut T,
            )
        }
    }

    /// Finds and reserves a contiguous run of `n` free slots using a
    /// first-fit linear scan over the bitmap.
    ///
    /// # Parameters
    ///
    /// * `n` — Number of consecutive free slots to claim.
    ///
    /// # Returns
    ///
    /// * `Some(start)` — First slot of the reserved run; bits
    ///   `start..start+n` are now set.
    /// * `None` — No run of length `n` exists.
    fn alloc_run(&self, n: usize) -> Option<usize> {
        let mut run = 0usize;
        let mut start = 0usize;
        for i in 0..self.num_slots {
            if !self.bit(i) {
                if run == 0 {
                    start = i;
                }
                run += 1;
                if run == n {
                    for j in start..start + n {
                        self.set_bit(j, true);
                    }
                    let new_live = self.live_count.get().saturating_add(n as u32);
                    self.live_count.set(new_live);
                    if new_live > self.max_live.get() {
                        self.max_live.set(new_live);
                    }
                    return Some(start);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    fn alloc_run_backwards(&self, n: usize) -> Option<usize> {
        let mut run = 0usize;
        for i in (0..self.num_slots).rev() {
            if !self.bit(i) {
                run += 1;
                if run == n {
                    let start = i;
                    for j in start..start + n {
                        self.set_bit(j, true);
                    }
                    let new_live = self.live_count.get().saturating_add(n as u32);
                    self.live_count.set(new_live);
                    if new_live > self.max_live.get() {
                        self.max_live.set(new_live);
                    }
                    return Some(start);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    /// Releases a previously-reserved run of slots back to the pool by clearing
    /// their occupancy bits. The slot bytes are left as-is; per-request `reset`
    /// plus the write-before-read discipline scope their reuse.
    ///
    /// # Parameters
    ///
    /// * `start` — First slot index of the run.
    /// * `n` — Number of slots to free.
    fn free_run(&self, start: usize, n: usize) {
        for j in start..start + n {
            self.set_bit(j, false);
        }
        self.live_count
            .set(self.live_count.get().saturating_sub(n as u32));
    }

    /// Reads bit `i` of the occupancy bitmap.
    #[inline]
    fn bit(&self, i: usize) -> bool {
        unsafe { (*self.base.as_ptr().add(i / 8)) & (1u8 << (i % 8)) != 0 }
    }

    /// Sets bit `i` of the occupancy bitmap to `v`.
    #[inline]
    fn set_bit(&self, i: usize, v: bool) {
        unsafe {
            let p = self.base.as_ptr().add(i / 8);
            if v {
                *p |= 1u8 << (i % 8);
            } else {
                *p &= !(1u8 << (i % 8));
            }
        }
    }
}

/// RAII owner of a value allocated from a [`BitmapAllocator`], analogous to
/// [`alloc::boxed::Box`]. Drops the value in place and releases its slots on
/// drop.
///
/// Sized to be cheap to embed in async state machines: `&BitmapAllocator` +
/// `(u16 start, u16 count)` = 8 bytes on a 32-bit target (12 bytes on
/// 64-bit). The data pointer is recomputed from the allocator base.
#[must_use = "dropping a McuSpdmBox without holding it would immediately free the underlying slots"]
pub struct McuSpdmBox<'a, T> {
    /// Borrow of the backing allocator; used to free slots on drop.
    alloc: &'a BitmapAllocator,
    /// First slot of the reserved run.
    start_slot: u16,
    /// Length of the run, in slots.
    num_slots: u16,
    /// Tells the borrow checker we exclusively own a `T`.
    _marker: PhantomData<&'a mut T>,
}

impl<T> McuSpdmBox<'_, T> {
    /// Returns a non-null typed pointer to the owned value.
    #[inline]
    fn ptr(&self) -> NonNull<T> {
        self.alloc.slot_ptr::<T>(self.start_slot)
    }
}

impl<T> Drop for McuSpdmBox<'_, T> {
    /// Drops the owned value in place, securely zero-wipes the memory slot, then releases the underlying
    /// slots back to the allocator's bitmap.
    fn drop(&mut self) {
        unsafe { core::ptr::drop_in_place(self.ptr().as_ptr()) };
        // Securely zero-wipe the underlying memory slots to prevent information leaks of stateful data.
        unsafe {
            core::ptr::write_bytes(
                self.ptr().as_ptr() as *mut u8,
                0,
                self.num_slots as usize * BITMAP_SLOT_SIZE,
            );
        }
        self.alloc
            .free_run(self.start_slot as usize, self.num_slots as usize);
    }
}

impl<T> core::ops::Deref for McuSpdmBox<'_, T> {
    type Target = T;

    /// Shared access to the owned `T`.
    fn deref(&self) -> &T {
        // SAFETY: slot is initialized, aligned, and exclusively owned by this
        // box for its lifetime.
        unsafe { &*self.ptr().as_ptr() }
    }
}

impl<T> core::ops::DerefMut for McuSpdmBox<'_, T> {
    /// Exclusive access to the owned `T`.
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: see `Deref`.
        unsafe { &mut *self.ptr().as_ptr() }
    }
}

/// RAII byte buffer allocated from a [`BitmapAllocator`].
///
/// Like [`McuSpdmBox<[u8; _]>`] but lets the holder shrink the logical
/// length and release the trailing slots back to the pool — designed
/// for receive paths that allocate `transport.mtu()` bytes and trim
/// down to the actual message size.
///
/// Sized to 8 bytes on a 32-bit target (12 on 64-bit). `slots_tail`
/// packs the slot count and the count of unused bytes in the last slot
/// into a single u16:
///
/// ```text
///  bit 15            6 5            0
/// ┌────────────────────┬─────────────┐
/// │   num_slots (10)   │ unused (6)  │
/// └────────────────────┴─────────────┘
/// ```
///
/// `num_slots` covers up to 1023 slots (= 64 KiB at SLOT_SIZE=64).
/// `unused` is the number of trailing bytes in the last slot that are
/// *not* part of the logical buffer; valid range 0..63. Logical length
/// is therefore `num_slots * SLOT_SIZE - unused`.
#[must_use = "dropping a BitmapBytes without holding it would immediately free the underlying slots"]
pub struct BitmapBytes<'a> {
    /// Borrow of the backing allocator; used to free slots on drop or
    /// shrink.
    alloc: &'a BitmapAllocator,
    /// First slot of the reserved run.
    start_slot: u16,
    /// Packed `(num_slots, unused_tail)` — see [`Self::pack`].
    slots_tail: u16,
}

impl BitmapBytes<'_> {
    /// Number of bits reserved for the slot-count field of `slots_tail`.
    const NUM_SLOTS_BITS: u32 = 10;
    /// Mask covering the slot-count field of `slots_tail` (low-aligned).
    const NUM_SLOTS_MASK: u16 = (1u16 << Self::NUM_SLOTS_BITS) - 1;
    /// Number of bits reserved for the unused-tail field of `slots_tail`.
    const TAIL_BITS: u32 = 6;
    /// Mask covering the unused-tail field of `slots_tail`.
    const TAIL_MASK: u16 = (1u16 << Self::TAIL_BITS) - 1;
    /// Maximum number of slots a single `BitmapBytes` can hold
    /// (1023, dictated by [`Self::NUM_SLOTS_BITS`]).
    pub const MAX_SLOTS: usize = (1usize << Self::NUM_SLOTS_BITS) - 1;
    /// Maximum byte length a single `BitmapBytes` can represent
    /// (`MAX_SLOTS * BITMAP_SLOT_SIZE` = 65 472 bytes by default).
    pub const MAX_LEN: usize = Self::MAX_SLOTS * BITMAP_SLOT_SIZE;

    /// Packs `(num_slots, unused)` into a single `u16`.
    ///
    /// # Parameters
    ///
    /// * `num_slots` — Slot-count component (`0..=MAX_SLOTS`).
    /// * `unused` — Count of trailing bytes in the final slot that
    ///   are *not* part of the logical buffer (`0..BITMAP_SLOT_SIZE`).
    ///
    /// # Returns
    ///
    /// `(num_slots << TAIL_BITS) | unused` — the encoded `slots_tail`
    /// field, debug-asserted to fit each field's width.
    #[inline]
    pub(crate) fn pack(num_slots: u16, unused: u8) -> u16 {
        debug_assert!(num_slots <= Self::MAX_SLOTS as u16);
        debug_assert!(unused < BITMAP_SLOT_SIZE as u8);
        ((num_slots & Self::NUM_SLOTS_MASK) << Self::TAIL_BITS) | (unused as u16 & Self::TAIL_MASK)
    }

    /// Extracts the slot-count component of `slots_tail`.
    #[inline]
    fn num_slots(&self) -> u16 {
        (self.slots_tail >> Self::TAIL_BITS) & Self::NUM_SLOTS_MASK
    }

    /// Extracts the unused-tail component of `slots_tail`.
    #[inline]
    fn unused_tail(&self) -> u16 {
        self.slots_tail & Self::TAIL_MASK
    }

    /// Returns the current valid length, in bytes.
    ///
    /// # Returns
    ///
    /// `num_slots * BITMAP_SLOT_SIZE - unused_tail` — the logical
    /// length seen by [`Self::as_slice`] / [`Self::as_mut_slice`] /
    /// the `Deref` implementations.
    pub fn len(&self) -> usize {
        self.num_slots() as usize * BITMAP_SLOT_SIZE - self.unused_tail() as usize
    }

    /// Returns `true` when [`Self::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total reserved capacity, in bytes.
    ///
    /// # Returns
    ///
    /// `num_slots * BITMAP_SLOT_SIZE`. Always `>= len()`; equal to
    /// `len()` after a [`Self::shrink`] to a slot boundary.
    pub fn capacity(&self) -> usize {
        self.num_slots() as usize * BITMAP_SLOT_SIZE
    }

    /// Computes the start-of-buffer pointer from the allocator base.
    ///
    /// # Returns
    ///
    /// `allocator.data + start_slot * BITMAP_SLOT_SIZE`.
    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `start_slot < BitmapAllocator::num_slots`, set at
        // allocation time; offset stays in-bounds of the data region.
        unsafe {
            self.alloc
                .data
                .as_ptr()
                .add(self.start_slot as usize * BITMAP_SLOT_SIZE)
        }
    }

    /// Returns a shared view of the valid bytes.
    ///
    /// # Returns
    ///
    /// Slice of length [`Self::len`] starting at the buffer base.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: slots are reserved for us; underlying memory was
        // initialized by writes through `as_mut_slice`; `len <= capacity`.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), self.len()) }
    }

    /// Returns an exclusive view of the full reserved capacity,
    /// suitable for passing to a transport `recv` API.
    ///
    /// # Returns
    ///
    /// Slice of length [`Self::capacity`]. Bytes outside `0..len()`
    /// are uninitialized and must be written before being read.
    #[inline]
    pub fn as_mut_capacity(&mut self) -> &mut [u8] {
        let cap = self.capacity();
        // SAFETY: slots are reserved and exclusively owned by `self`.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), cap) }
    }

    /// Returns an exclusive view of the valid bytes.
    ///
    /// # Returns
    ///
    /// Mutable slice of length [`Self::len`] starting at the buffer base.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len();
        // SAFETY: see `as_mut_capacity`.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), len) }
    }

    /// Shrinks the logical length to `new_len` and releases any
    /// trailing slots that are no longer needed back to the pool.
    ///
    /// Used by receive paths that allocate the transport MTU and then
    /// trim down to the actual message length, returning the unused
    /// tail slots so the responder can immediately reuse them.
    ///
    /// # Parameters
    ///
    /// * `new_len` — New logical length in bytes. Must be `<= len()`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — [`Self::len`] now equals `new_len`; trailing slots
    ///   beyond `ceil(new_len / SLOT_SIZE)` have been freed.
    ///
    /// # Errors
    ///
    /// * `OUT_OF_MEMORY` — `new_len > len()` (the operation cannot
    ///   grow the buffer).
    pub fn shrink(&mut self, new_len: usize) -> McuResult<()> {
        if new_len > self.len() {
            return Err(ERR_OUT_OF_MEMORY);
        }
        let needed_slots = new_len.div_ceil(BITMAP_SLOT_SIZE).max(1) as u16;
        let cur_slots = self.num_slots();
        if needed_slots < cur_slots {
            let free_from = self.start_slot as usize + needed_slots as usize;
            let free_count = (cur_slots - needed_slots) as usize;
            self.alloc.free_run(free_from, free_count);
        }
        let unused = (needed_slots as usize * BITMAP_SLOT_SIZE - new_len) as u8;
        self.slots_tail = Self::pack(needed_slots, unused);
        Ok(())
    }
}

impl Drop for BitmapBytes<'_> {
    /// Releases every slot reserved by this buffer back to the
    /// allocator's bitmap. Plain `[u8]` has no drop glue, so no
    /// per-element teardown is needed.
    fn drop(&mut self) {
        self.alloc
            .free_run(self.start_slot as usize, self.num_slots() as usize);
    }
}

impl core::ops::Deref for BitmapBytes<'_> {
    type Target = [u8];
    /// Shared access to the valid bytes; equivalent to [`Self::as_slice`].
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::ops::DerefMut for BitmapBytes<'_> {
    /// Exclusive access to the valid bytes; equivalent to
    /// [`Self::as_mut_slice`].
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// Compile-time check that `BitmapBytes` stays compact (8 bytes on
/// 32-bit targets). The responder embeds many of these in async state
/// machines, so growth here is felt across the firmware.
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<BitmapBytes<'_>>() == 8);

// ---------------------------------------------------------------------------
// Static allocator cell
// ---------------------------------------------------------------------------

/// One-shot cell that holds a [`BitmapAllocator`] as a `static`, returning a
/// `&'static BitmapAllocator` after the single call to [`Self::init_once`].
///
/// `BitmapAllocator` is deliberately `!Sync` because its interior mutability
/// is single-task by construction. We cannot wrap it in `OnceLock` /
/// `OnceCell::sync` (those require `Sync`). Instead we hand-roll the minimal
/// pattern: an `UnsafeCell<MaybeUninit<…>>` accessible via a `Sync` outer
/// wrapper whose contract requires the caller to enforce the single-task
/// invariant.
///
/// # Safety contract
///
/// * [`Self::init_once`] must be called at most once for the lifetime of the
///   program. A second call invokes UB. Caller may enforce this with their
///   own "this task ran" flag or by structural single-task ownership (the
///   common pattern: one cell per `#[embassy_executor::task]`).
/// * After `init_once`, the returned `&'static BitmapAllocator` is the
///   canonical handle for that allocator and may be freely shared within the
///   owning task. Sharing across tasks is undefined behavior.
/// * The byte region passed to `init_once` must outlive every allocation
///   produced from the returned allocator. In practice this means the region
///   is itself `static`.
pub struct StaticBitmapAllocatorCell {
    inner: UnsafeCell<MaybeUninit<BitmapAllocator>>,
}

// SAFETY: The cell is `Sync` so it can appear in `static`. Actual access to
// `inner` is `unsafe` and the contract requires single-task usage.
unsafe impl Sync for StaticBitmapAllocatorCell {}

impl StaticBitmapAllocatorCell {
    /// Constructs an empty cell. The contained allocator is uninitialized
    /// until [`Self::init_once`] is called.
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Initializes the contained `BitmapAllocator` in place over
    /// `[ptr, ptr + capacity)` and returns a `&'static` handle to it.
    ///
    /// # Safety
    ///
    /// All of the safety conditions on [`BitmapAllocator::new`] apply, plus:
    ///
    /// * MUST be called at most once for this cell.
    /// * Must not be called concurrently with any access to the cell.
    pub unsafe fn init_once(
        &'static self,
        ptr: NonNull<u8>,
        capacity: usize,
    ) -> &'static BitmapAllocator {
        let slot = self.inner.get();
        let alloc = BitmapAllocator::new(ptr, capacity);
        (*slot).write(alloc);
        (*slot).assume_init_ref()
    }
}

impl Default for StaticBitmapAllocatorCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

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

    #[test]
    fn live_slots_balance_alloc_drop() {
        let (alloc, _buf) = make_alloc(4 * 1024);
        assert_eq!(alloc.live_slots(), 0);

        let a = alloc.alloc_bytes(100).unwrap();
        assert_eq!(alloc.live_slots(), 2); // 100 B over 64 B slots = 2 slots

        let b = alloc.alloc_bytes(64).unwrap();
        assert_eq!(alloc.live_slots(), 3);

        drop(a);
        assert_eq!(alloc.live_slots(), 1);
        drop(b);
        assert_eq!(alloc.live_slots(), 0);
    }

    #[test]
    fn max_live_tracks_peak() {
        let (alloc, _buf) = make_alloc(4 * 1024);
        assert_eq!(alloc.max_live_slots(), 0);

        let a = alloc.alloc_bytes(64).unwrap();
        let b = alloc.alloc_bytes(64).unwrap();
        let c = alloc.alloc_bytes(64).unwrap();
        assert_eq!(alloc.max_live_slots(), 3);

        drop(c);
        // max stays at 3 even after free
        assert_eq!(alloc.max_live_slots(), 3);

        let _d = alloc.alloc_bytes(64).unwrap();
        // back at 3 live; max unchanged
        assert_eq!(alloc.live_slots(), 3);
        assert_eq!(alloc.max_live_slots(), 3);

        let _e = alloc.alloc_bytes(64).unwrap();
        // now 4 live → new peak
        assert_eq!(alloc.live_slots(), 4);
        assert_eq!(alloc.max_live_slots(), 4);

        drop(a);
        drop(b);
    }

    #[test]
    fn largest_free_run_finds_holes() {
        let (alloc, _buf) = make_alloc(8 * 1024);
        let total = alloc.num_slots();
        assert_eq!(alloc.largest_free_run(), total);

        let a = alloc.alloc_bytes(64).unwrap();
        let b = alloc.alloc_bytes(64).unwrap();
        let c = alloc.alloc_bytes(64).unwrap();
        // 3 slots taken at the bottom; rest free.
        assert_eq!(alloc.largest_free_run(), total - 3);

        drop(b); // hole in the middle
                 // Free regions: [bit 1..2] (1 slot) + [bit 3..total] (total-3 slots).
                 // Largest = total - 3.
        assert_eq!(alloc.largest_free_run(), total - 3);
        drop(a);
        drop(c);
        assert_eq!(alloc.largest_free_run(), total);
    }

    #[test]
    fn bidirectional_split_allocation() {
        let (alloc, _buf) = make_alloc(8 * 1024);
        let total = alloc.num_slots();

        let low = alloc.alloc_bytes(2 * BITMAP_SLOT_SIZE).unwrap();
        let high = alloc.alloc(0u64).unwrap();

        assert_eq!(low.start_slot, 0);
        assert_eq!(high.start_slot as usize, total - 1);
        assert_eq!(alloc.live_slots(), 3);

        drop(low);
        drop(high);
        assert_eq!(alloc.live_slots(), 0);
    }

    #[test]
    fn oom_does_not_leak_slots() {
        let (alloc, _buf) = make_alloc(4 * 1024);
        let total = alloc.num_slots();

        // Allocate up to (just under) capacity; one of these will be at the
        // limit. Then attempt an oversized request and verify nothing leaked.
        let huge = (total * BITMAP_SLOT_SIZE) + 1;
        assert!(alloc.alloc_bytes(huge).is_err());
        assert_eq!(alloc.live_slots(), 0);
    }

    #[test]
    fn drop_alloc_box_releases_slots() {
        let (alloc, _buf) = make_alloc(4 * 1024);
        assert_eq!(alloc.live_slots(), 0);
        {
            let _b = alloc.alloc(0u64).unwrap();
            assert_eq!(alloc.live_slots(), 1); // u64 fits in one slot
        }
        assert_eq!(alloc.live_slots(), 0);
    }

    /// Deterministic fragmentation soak — emulates the steady-state SPDM
    /// responder allocation mix and verifies that an 8 KiB large-message
    /// allocation can still succeed after many request cycles under
    /// realistic interleaving of long-lived (transcript / session) and
    /// transient (request / response framing) allocations.
    ///
    /// This test gates Phase 6 (delete static large buffer). If first-fit
    /// fragments the bitmap enough that the 8 KiB contiguous run cannot
    /// be allocated after the simulated workload, we must add directional
    /// allocation (low for persistent, high for large) before deleting the
    /// static buffer.
    ///
    /// Allocation mix per request cycle:
    ///   * recv-buffer (~1.5 KiB) — transient
    ///   * response-buffer (~1.5 KiB) — transient
    ///   * 1-2 small scratch allocations (~256 B each) — transient
    ///
    /// Long-lived (allocated once at "session start", held for whole soak):
    ///   * SessionInfo placeholder (~1 KiB)
    ///   * Transcript hashes — VCA, M1, L1, TH (4 × 256 B)
    ///
    /// Cycles: 50 request cycles, all transients drop at end of each cycle.
    ///
    /// At the end of the soak, attempt an 8 KiB allocation for a hypothetical
    /// CHUNK_GET large response. Pass means the bitmap allocator (with simple
    /// first-fit) can sustain the realistic workload without fragmenting too
    /// badly. Fail means we need directional allocation.
    #[test]
    fn fragmentation_soak_8k_alloc_after_realistic_workload() {
        // 16 KiB pool — close to the realistic per-task budget for our
        // platform after deleting the static large buffer.
        let (alloc, _buf) = make_alloc(16 * 1024);

        // Phase A — bring up the "session": one big object + four transcript
        // hashes. These hold their slots for the whole soak.
        let _session = alloc.alloc_bytes(1024).expect("session alloc");
        let _vca = alloc.alloc_bytes(256).expect("vca alloc");
        let _m1 = alloc.alloc_bytes(256).expect("m1 alloc");
        let _l1 = alloc.alloc_bytes(256).expect("l1 alloc");
        let _th = alloc.alloc_bytes(256).expect("th alloc");

        let baseline_live = alloc.live_slots();
        assert!(baseline_live > 0);

        // Phase B — run 50 request cycles of transient churn.
        for cycle in 0..50 {
            {
                let _recv = alloc
                    .alloc_bytes(1536)
                    .unwrap_or_else(|_| panic!("recv alloc failed at cycle {}", cycle));
                let _resp = alloc
                    .alloc_bytes(1536)
                    .unwrap_or_else(|_| panic!("resp alloc failed at cycle {}", cycle));
                let _scratch1 = alloc
                    .alloc_bytes(256)
                    .unwrap_or_else(|_| panic!("scratch1 alloc failed at cycle {}", cycle));
                let _scratch2 = alloc
                    .alloc_bytes(256)
                    .unwrap_or_else(|_| panic!("scratch2 alloc failed at cycle {}", cycle));
                // all transients drop here
            }
            // After cycle, live count must be back to baseline.
            assert_eq!(
                alloc.live_slots(),
                baseline_live,
                "transient leak at cycle {}",
                cycle
            );
        }

        // Phase C — record fragmentation state, then attempt the 8 KiB large
        // allocation. This is the GATE: if it fails, Phase 6 needs directional
        // allocation before deleting the static buffer.
        let largest_run_slots = alloc.largest_free_run();
        let largest_run_bytes = largest_run_slots * BITMAP_SLOT_SIZE;
        let large = alloc.alloc_bytes(8 * 1024);

        match large {
            Ok(buf) => {
                assert_eq!(buf.len(), 8 * 1024);
                // Soak passes — first-fit holds up.
            }
            Err(_) => {
                panic!(
                    "FRAGMENTATION SOAK FAILED: 8 KiB allocation failed after 50 cycles. \
                     baseline_live={}, largest_free_run={} slots ({} bytes). \
                     Phase 6 (delete static large buffer) needs directional allocation.",
                    baseline_live, largest_run_slots, largest_run_bytes
                );
            }
        }
    }
}
