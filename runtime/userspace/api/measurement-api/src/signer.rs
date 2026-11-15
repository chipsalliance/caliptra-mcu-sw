// Licensed under the Apache-2.0 license

use crate::ScratchAlloc;
use crate::{
    sign_with_exported_cdi, ExportedCdiSigningInput, ATTESTATION_MLDSA87_SIGNATURE_SIZE,
    ATTESTATION_P384_DIGEST_SIZE, ATTESTATION_P384_SIGNATURE_SIZE,
    EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE,
};
use mcu_caliptra_api::error::{CaliptraApiError, CaliptraApiResult};
use mcu_caliptra_api::ocp_lock::{EndorsementAlgorithm, OcpLockSigner};

/// DPE-backed OCP LOCK signer rooted at the Measurement API's configured
/// `EXPORT_CDI_TARGET`, using the caller task's scratch allocator for
/// mailbox request and response buffers.
pub struct CaliptraDpeSigner<'a, A: ScratchAlloc> {
    algorithm: EndorsementAlgorithm,
    scratch: &'a A,
}

impl<'a, A: ScratchAlloc> CaliptraDpeSigner<'a, A> {
    pub fn new(scratch: &'a A) -> Self {
        Self {
            algorithm: EndorsementAlgorithm::EcdsaP384Sha384,
            scratch,
        }
    }

    pub fn with_algorithm(algorithm: EndorsementAlgorithm, scratch: &'a A) -> Self {
        Self { algorithm, scratch }
    }
}

impl<A: ScratchAlloc> OcpLockSigner for CaliptraDpeSigner<'_, A> {
    fn algorithm(&self) -> EndorsementAlgorithm {
        self.algorithm
    }

    fn signature_size(&self) -> usize {
        match self.algorithm {
            EndorsementAlgorithm::EcdsaP384Sha384 => ATTESTATION_P384_SIGNATURE_SIZE,
            EndorsementAlgorithm::MlDsa87 => ATTESTATION_MLDSA87_SIGNATURE_SIZE,
        }
    }

    async fn sign(
        &self,
        _label: &[u8],
        data: &[u8],
        signature: &mut [u8],
    ) -> CaliptraApiResult<()> {
        let sig_size = self.signature_size();
        if signature.len() < sig_size {
            return Err(CaliptraApiError::InvalidArgBufferTooSmall);
        }

        let signing_input = match self.algorithm {
            EndorsementAlgorithm::EcdsaP384Sha384 => {
                let digest: &[u8; ATTESTATION_P384_DIGEST_SIZE] = data
                    .try_into()
                    .map_err(|_| CaliptraApiError::InvalidArgDigestSize)?;
                ExportedCdiSigningInput::EccP384Digest(digest)
            }
            EndorsementAlgorithm::MlDsa87 => {
                if data.is_empty() || data.len() > EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE {
                    return Err(CaliptraApiError::InvalidArgDigestSize);
                }
                ExportedCdiSigningInput::Mldsa87Raw(data)
            }
        };

        sign_with_exported_cdi(self.scratch, None, signing_input, signature)
            .await
            .map_err(|_| CaliptraApiError::InvalidResponse)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use mcu_error::McuResult;
    use std::vec::Vec;

    struct TestAlloc;

    impl ScratchAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(std::vec![0; len])
        }
    }

    fn block_on<F: Future>(mut future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut future = unsafe { Pin::new_unchecked(&mut future) };
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("unexpected pending future in unit test"),
        }
    }

    #[test]
    fn test_caliptra_dpe_signer_buffer_too_small() {
        let scratch = TestAlloc;
        let signer = CaliptraDpeSigner::new(&scratch);
        let digest = [0xAA; ATTESTATION_P384_DIGEST_SIZE];
        let mut small_sig = [0u8; ATTESTATION_P384_SIGNATURE_SIZE - 1];
        let res = block_on(signer.sign(b"label", &digest, &mut small_sig));
        assert_eq!(res, Err(CaliptraApiError::InvalidArgBufferTooSmall));
    }

    #[test]
    fn test_caliptra_dpe_signer_mldsa87_buffer_too_small() {
        let scratch = TestAlloc;
        let signer = CaliptraDpeSigner::with_algorithm(EndorsementAlgorithm::MlDsa87, &scratch);
        let tbs = [0xBB; 64];
        let mut small_sig = [0u8; ATTESTATION_MLDSA87_SIGNATURE_SIZE - 1];
        let res = block_on(signer.sign(b"label", &tbs, &mut small_sig));
        assert_eq!(res, Err(CaliptraApiError::InvalidArgBufferTooSmall));
    }

    #[test]
    fn test_caliptra_dpe_signer_invalid_digest_size() {
        let scratch = TestAlloc;
        let signer = CaliptraDpeSigner::new(&scratch);
        let bad_digest = [0xAA; ATTESTATION_P384_DIGEST_SIZE - 1];
        let mut sig = [0u8; ATTESTATION_P384_SIGNATURE_SIZE];
        let res = block_on(signer.sign(b"label", &bad_digest, &mut sig));
        assert_eq!(res, Err(CaliptraApiError::InvalidArgDigestSize));
    }

    #[test]
    fn test_caliptra_dpe_signer_mldsa87_empty_and_oversized_tbs() {
        let scratch = TestAlloc;
        let signer = CaliptraDpeSigner::with_algorithm(EndorsementAlgorithm::MlDsa87, &scratch);
        let mut sig = [0u8; ATTESTATION_MLDSA87_SIGNATURE_SIZE];

        assert_eq!(
            block_on(signer.sign(b"label", &[], &mut sig)),
            Err(CaliptraApiError::InvalidArgDigestSize)
        );

        let oversized = [0xCC; EXPORTED_CDI_MAX_MLDSA87_TBS_SIZE + 1];
        assert_eq!(
            block_on(signer.sign(b"label", &oversized, &mut sig)),
            Err(CaliptraApiError::InvalidArgDigestSize)
        );
    }

    #[test]
    fn test_caliptra_dpe_signer_fails_when_measurement_api_not_initialized() {
        let scratch = TestAlloc;
        let signer = CaliptraDpeSigner::new(&scratch);
        let digest = [0xAA; ATTESTATION_P384_DIGEST_SIZE];
        let mut sig = [0u8; ATTESTATION_P384_SIGNATURE_SIZE];
        assert_eq!(
            block_on(signer.sign(b"label", &digest, &mut sig)),
            Err(CaliptraApiError::InvalidResponse)
        );
    }
}
