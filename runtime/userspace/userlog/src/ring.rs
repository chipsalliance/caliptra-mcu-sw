// Licensed under the Apache-2.0 license

//! SPSC byte ring of `0x00`-terminated frames, backed by [`heapless::spsc::Queue`]
//! in a `critical_section::Mutex<RefCell>` so it is `Sync` with no `unsafe` here.

use core::cell::RefCell;
use critical_section::Mutex;
use heapless::spsc::Queue;

pub struct ByteRing<const N: usize> {
    inner: Mutex<RefCell<Queue<u8, N>>>,
}

impl<const N: usize> ByteRing<N> {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Queue::new())),
        }
    }

    /// Push an entire slice atomically. Returns `false` and writes nothing if it
    /// does not fit in the free space. Single-producer only.
    pub fn push_slice(&self, data: &[u8]) -> bool {
        critical_section::with(|cs| {
            let mut q = self.inner.borrow(cs).borrow_mut();
            if q.capacity() - q.len() < data.len() {
                return false;
            }
            for &b in data {
                let _ = q.enqueue(b);
            }
            true
        })
    }

    /// Pop one `0x00`-terminated frame into `out`, returning its length. Returns
    /// `None` if no complete frame is available. A frame longer than `out` is
    /// still fully consumed (excess discarded) so the stream stays aligned.
    /// Single-consumer only.
    pub fn pop_frame(&self, out: &mut [u8]) -> Option<usize> {
        critical_section::with(|cs| {
            let mut q = self.inner.borrow(cs).borrow_mut();
            // Scan for the terminator without consuming; bail if not yet present.
            let mut frame_len = 0usize;
            let mut terminated = false;
            for &b in q.iter() {
                frame_len += 1;
                if b == 0 {
                    terminated = true;
                    break;
                }
            }
            if !terminated {
                return None;
            }
            let mut copied = 0usize;
            for _ in 0..frame_len {
                let b = q.dequeue().unwrap();
                if copied < out.len() {
                    out[copied] = b;
                    copied += 1;
                }
            }
            Some(copied)
        })
    }
}

impl<const N: usize> Default for ByteRing<N> {
    fn default() -> Self {
        Self::new()
    }
}
