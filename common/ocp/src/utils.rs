// Licensed under the Apache-2.0 license

//! Panic-free utilities for the OCP crate.

use crate::error::OcpError;

/// Copy `src` into `dst` without panicking.
///
/// Returns [`OcpError::SliceLengthMismatch`] if the two slices differ in
/// length. This is the non-panicking equivalent of
/// [`<[u8]>::copy_from_slice`].
pub fn try_copy_from_slice(dst: &mut [u8], src: &[u8]) -> Result<(), OcpError> {
    if dst.len() != src.len() {
        return Err(OcpError::SliceLengthMismatch);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_equal_length() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [0u8; 4];
        try_copy_from_slice(&mut dst, &src).unwrap();
        assert_eq!(dst, src);
    }

    #[test]
    fn copy_empty() {
        try_copy_from_slice(&mut [], &[]).unwrap();
    }

    #[test]
    fn dst_shorter_than_src() {
        let mut dst = [0u8; 2];
        assert_eq!(
            try_copy_from_slice(&mut dst, &[1, 2, 3]),
            Err(OcpError::SliceLengthMismatch),
        );
    }

    #[test]
    fn src_shorter_than_dst() {
        let mut dst = [0u8; 4];
        assert_eq!(
            try_copy_from_slice(&mut dst, &[1, 2]),
            Err(OcpError::SliceLengthMismatch),
        );
    }
}
