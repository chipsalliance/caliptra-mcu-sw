// Licensed under the Apache-2.0 license

use romtime::otp::Otp;

/// Verifies the authenticity and integrity of the provided image header
/// against the device's fuse state.
///
/// The image header is user-defined and it is up to the implementer to parse the header
/// and enforce any required policies.
///
/// Parameters:
///   header:  Raw bytes of the image header
///   otp:  Reference to the OTP driver for reading fuse values on demand
///
/// Returns:
///   true if every required check passes.
///   false on any structural, policy, or cryptographic failure.
pub trait ImageVerifier {
    fn verify_header(&self, header: &[u8], otp: &Otp) -> bool;
}
