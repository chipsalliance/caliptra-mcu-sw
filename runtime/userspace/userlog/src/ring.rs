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
            if !q.iter().any(|&b| b == 0) {
                return None;
            }
            let mut copied = 0usize;
            while let Some(b) = q.dequeue() {
                if copied < out.len() {
                    out[copied] = b;
                    copied += 1;
                }
                if b == 0 {
                    return Some(copied);
                }
            }
            None
        })
    }
}

impl<const N: usize> Default for ByteRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteRing;

    #[test]
    fn incomplete_frame_is_retained_without_touching_output() {
        let ring = ByteRing::<16>::new();
        let mut out = [0xa5; 8];
        assert!(ring.push_slice(b"abc"));
        assert_eq!(ring.pop_frame(&mut out), None);
        assert_eq!(out, [0xa5; 8]);

        assert!(ring.push_slice(b"\0next\0"));
        assert_eq!(ring.pop_frame(&mut out), Some(4));
        assert_eq!(&out[..4], b"abc\0");
        assert_eq!(ring.pop_frame(&mut out), Some(5));
        assert_eq!(&out[..5], b"next\0");
        assert_eq!(ring.pop_frame(&mut out), None);
    }

    #[test]
    fn short_output_consumes_only_the_first_frame_across_wraparound() {
        let ring = ByteRing::<8>::new();
        assert!(ring.push_slice(b"a\0bc\0"));
        let mut short = [0; 1];
        assert_eq!(ring.pop_frame(&mut short), Some(1));
        assert_eq!(&short, b"a");

        assert!(ring.push_slice(b"def\0"));
        let mut out = [0; 4];
        assert_eq!(ring.pop_frame(&mut out), Some(3));
        assert_eq!(&out[..3], b"bc\0");
        assert_eq!(ring.pop_frame(&mut out), Some(4));
        assert_eq!(&out, b"def\0");
        assert_eq!(ring.pop_frame(&mut out), None);
    }

    #[test]
    fn empty_output_consumes_one_frame_and_delimiters_count_when_copied() {
        let ring = ByteRing::<8>::new();
        assert!(ring.push_slice(b"\0abc\0"));
        assert_eq!(ring.pop_frame(&mut []), Some(0));
        let mut out = [0xa5; 4];
        assert_eq!(ring.pop_frame(&mut out), Some(4));
        assert_eq!(&out, b"abc\0");
        assert_eq!(ring.pop_frame(&mut []), None);

        assert!(ring.push_slice(b"\0"));
        assert_eq!(ring.pop_frame(&mut out), Some(1));
        assert_eq!(out[0], 0);
    }
}
