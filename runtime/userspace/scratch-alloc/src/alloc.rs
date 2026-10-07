// Licensed under the Apache-2.0 license

//! Scratch-allocation contract shared by the Caliptra mailbox APIs.
//!
//! Two traits with distinct jobs:
//!
//! * [`ScratchAlloc`] — *allocates*. Implemented by the type that owns backing
//!   storage. [`BitmapAllocator`](crate::BitmapAllocator) is the production
//!   implementation.
//! * [`ScratchAllocProvider`] — *points at* an allocator. Implemented by the
//!   types that hold one, and by allocators themselves as the identity.
//!
//! # Extending
//!
//! **A new caller of the mailbox APIs.** Own a buffer, build a
//! `BitmapAllocator` over it, and implement [`ScratchAllocProvider`] on the
//! owning type. Hand [`ScratchAllocProvider::allocator`] to the APIs. Do not
//! implement [`ScratchAlloc`] by forwarding to the allocator you hold — see
//! below.
//!
//! **A new mailbox API.** Take `&A where A: ScratchAlloc` and stage request
//! and response bytes in it. Nothing else needs to change.
//!
//! **A new allocator.** Implement [`ScratchAlloc`], plus
//! [`ScratchAllocProvider`] as the identity. Weigh the cost first:
//! [`ScratchAlloc`] has a generic associated type, so it is not object-safe
//! and every `<A: ScratchAlloc>` API is compiled once per implementing type. A
//! second implementation re-emits every mailbox API and command handler
//! reachable from it. Holding the line at one production allocator is why
//! owners *provide* an allocator rather than *being* one.

use core::ops::DerefMut;
use mcu_error::McuResult;

/// Allocates scratch for one Caliptra mailbox exchange.
///
/// Request and response bytes live in [`Self::Buf`] rather than on the stack,
/// so an async task's future does not grow by the multi-kilobyte Caliptra
/// `Cm*Req` payload it happens to carry.
///
/// # Contract
///
/// - [`alloc`](Self::alloc) yields exactly `len` bytes, or an error when the
///   storage cannot satisfy the request. Exhaustion is reported, never
///   panicked on.
/// - Contents are **uninitialised**; callers write before they read.
/// - [`Self::Buf`] borrows the allocator and returns its storage on drop, so a
///   buffer can never outlive the allocator that produced it.
/// - [`alloc`](Self::alloc) takes `&self`, so implementors need interior
///   mutability and own the soundness argument for it. The production
///   allocator is `!Send + !Sync`, confining an instance to one owner.
pub trait ScratchAlloc {
    /// RAII guard over the allocated bytes, released on `Drop`.
    type Buf<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Allocates `len` uninitialised bytes of scratch.
    fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>>;
}

/// Points at the [`ScratchAlloc`] a type owns.
///
/// # Contract
///
/// - [`allocator`](Self::allocator) returns the same instance for the lifetime
///   of `self`; a caller may hold a buffer from one call across another.
/// - A [`ScratchAlloc`] implements this as the identity (`type Alloc = Self`),
///   so a call site reads the same whether it holds the allocator itself or a
///   type that merely owns one.
pub trait ScratchAllocProvider {
    /// The allocator that owns the backing storage.
    type Alloc: ScratchAlloc;

    /// Borrows the allocator to pass to a generic mailbox API.
    fn allocator(&self) -> &Self::Alloc;
}
