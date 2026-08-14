// Licensed under the Apache-2.0 license

//! Minimal two-future `select` for the HEARTBEAT liveness run loop.
//!
//! Races `recv_request` against the watchdog `sleep_ms` so an idle session can
//! be torn down without pulling in an external `select` combinator (the
//! vendored offline build has no `embassy-futures`). Polls `a` first each wake
//! so an arriving request is always preferred over a simultaneously-expiring
//! timer.
//!
//! Compiled only when the `spdm-set-heartbeat` feature is enabled.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Which branch of a [`select`] completed first.
pub(crate) enum Either<A, B> {
    /// The first future (`a`) completed; carries its output.
    First(A),
    /// The second future (`b`) completed; carries its output.
    Second(B),
}

/// Poll `a` and `b` concurrently, resolving to [`Either`] as soon as one
/// completes. The loser is dropped (its side effects, if any, are abandoned),
/// so both futures must be cancellation-safe.
pub(crate) fn select<A, B>(a: A, b: B) -> Select<A, B> {
    Select { a, b }
}

pub(crate) struct Select<A, B> {
    a: A,
    b: B,
}

impl<A: Future, B: Future> Future for Select<A, B> {
    type Output = Either<A::Output, B::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: we never move `a` or `b` out of `self`; we only re-pin them in
        // place for polling, and `self` is already pinned by the caller.
        let this = unsafe { self.get_unchecked_mut() };
        let a = unsafe { Pin::new_unchecked(&mut this.a) };
        if let Poll::Ready(out) = a.poll(cx) {
            return Poll::Ready(Either::First(out));
        }
        let b = unsafe { Pin::new_unchecked(&mut this.b) };
        if let Poll::Ready(out) = b.poll(cx) {
            return Poll::Ready(Either::Second(out));
        }
        Poll::Pending
    }
}
