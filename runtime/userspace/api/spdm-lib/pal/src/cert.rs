// Licensed under the Apache-2.0 license

//! SPDM certificate-store adapter for the `spdm-lib` PAL.
//!
//! Maps SPDM slot IDs (`0`, `2`, `3`) and [`SpdmPalAsymAlgo`] values onto the
//! protocol-neutral [`caliptra_mcu_cert_store`] roles (`Vendor`, `Owner`,
//! `Tenant`) and [`CertificateAlgorithm`] values.

use super::measurements::MeasurementProvider;
use super::*;
#[cfg(feature = "set-certificate")]
use caliptra_mcu_cert_store::errors as cert_errors;
use caliptra_mcu_cert_store::{
    CertificateAlgorithm, EndorsementRole, EndorsementStorage, DPE_LEAF_LABEL,
};
use caliptra_mcu_spdm_traits::{SigningInput, SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};

#[inline]
const fn role_spdm_slot(role: EndorsementRole) -> u8 {
    match role {
        EndorsementRole::Vendor => 0,
        EndorsementRole::Owner => 2,
        EndorsementRole::Tenant => 3,
    }
}

#[inline]
const fn slot_role(spdm_slot: u8) -> Option<EndorsementRole> {
    match spdm_slot {
        0 => Some(EndorsementRole::Vendor),
        2 => Some(EndorsementRole::Owner),
        3 => Some(EndorsementRole::Tenant),
        _ => None,
    }
}

#[inline]
const fn cert_algo(algo: SpdmPalAsymAlgo) -> CertificateAlgorithm {
    match algo {
        SpdmPalAsymAlgo::EccP384 => CertificateAlgorithm::EccP384,
        SpdmPalAsymAlgo::MlDsa87 => CertificateAlgorithm::MlDsa87,
    }
}

#[cfg(feature = "set-certificate")]
fn map_set_cert_error(err: mcu_error::McuErrorCode) -> mcu_error::McuErrorCode {
    if err == cert_errors::STORAGE_BUSY {
        caliptra_mcu_spdm_codec::errors::SPDM_BUSY
    } else if err == cert_errors::STORAGE_ERROR {
        caliptra_mcu_spdm_codec::errors::SPDM_OPERATION_FAILED
    } else if err.domain() == mcu_error::domain::CERT_STORE {
        caliptra_mcu_spdm_codec::errors::SPDM_INVALID_REQUEST
    } else {
        err
    }
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

impl<M: MeasurementProvider, S: EndorsementStorage> SpdmPalCertStore for McuSpdmPal<M, S> {
    fn supported_slots(&self) -> u8 {
        let mut mask = 0u8;
        for role in EndorsementRole::ALL {
            if self.cert_store.cert_slot(role).is_supported() {
                mask |= 1 << role_spdm_slot(role);
            }
        }
        mask
    }

    fn provisioned_slots(&self, algo: SpdmPalAsymAlgo) -> u8 {
        let algo = cert_algo(algo);
        let mut mask = 0u8;
        for role in EndorsementRole::ALL {
            if self.cert_store.cert_slot(role).is_provisioned(algo) {
                mask |= 1 << role_spdm_slot(role);
            }
        }
        mask
    }

    async fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .cert_slot(role)
            .endorsement_capacity(cert_algo(algo))
    }

    #[inline]
    #[cfg(feature = "set-certificate")]
    fn set_certificate_authorized(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _key_pair_id: u8,
        _cert_model: u8,
        _erase: bool,
    ) -> bool {
        slot_role(slot)
            .map(|role| self.cert_store.cert_slot(role).is_writable())
            .unwrap_or(false)
    }

    #[cfg(feature = "set-certificate")]
    async fn validate_set_certificate_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .validate_endorsement_chain(
                self.allocator,
                role,
                key_pair_id,
                cert_model,
                root_hash,
                cert_chain,
            )
            .await
            .map_err(map_set_cert_error)
    }

    async fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .cert_chain_len(self.allocator, role, cert_algo(algo))
            .await
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .cert_slot(role)
            .root_cert_hash(cert_algo(algo), out)
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .read_cert_chain(self.allocator, role, cert_algo(algo), offset, dst)
            .await
    }

    async fn sign(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        signing_input: SigningInput<'_>,
        signature: &mut [u8],
    ) -> McuResult<usize> {
        let _role = slot_role(slot).ok_or(INVARIANT)?;
        caliptra_mcu_measurement_api::sign(
            self.allocator,
            &DPE_LEAF_LABEL,
            signing_input,
            signature,
        )
        .await
        .map_err(|_| INTERNAL_BUG)
    }

    #[cfg(feature = "set-certificate")]
    async fn write_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<()> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .write_endorsement_chain(
                role,
                cert_algo(algo),
                key_pair_id,
                cert_info,
                root_hash,
                data,
            )
            .await
            .map_err(map_set_cert_error)
    }

    async fn begin_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        _root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let role = slot_role(slot).ok_or(INVARIANT)?;
            self.cert_store
                .begin_write_endorsement_stream(
                    role,
                    cert_algo(algo),
                    key_pair_id,
                    cert_info,
                    data_len,
                )
                .await
                .map_err(map_set_cert_error)
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, key_pair_id, cert_info, _root_hash, data_len);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn write_cert_chain_stream_chunk(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        data: &[u8],
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let role = slot_role(slot).ok_or(INVARIANT)?;
            self.cert_store
                .write_endorsement_stream_chunk(role, cert_algo(algo), offset, data)
                .await
                .map_err(map_set_cert_error)
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, offset, data);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn finish_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let role = slot_role(slot).ok_or(INVARIANT)?;
            self.cert_store
                .finish_write_endorsement_stream(
                    self.allocator,
                    role,
                    cert_algo(algo),
                    key_pair_id,
                    cert_info,
                    root_hash,
                    data_len,
                )
                .await
                .map_err(map_set_cert_error)
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, key_pair_id, cert_info, root_hash, data_len);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn abort_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let role = slot_role(slot).ok_or(INVARIANT)?;
            self.cert_store
                .abort_write_endorsement_stream(role, cert_algo(algo))
                .await
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo);
            Ok(())
        }
    }

    #[cfg(feature = "set-certificate")]
    async fn erase_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        let role = slot_role(slot).ok_or(INVARIANT)?;
        self.cert_store
            .erase_endorsement_chain(role, cert_algo(algo))
            .await
            .map_err(map_set_cert_error)
    }

    fn key_pair_id(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u8> {
        let role = slot_role(slot)?;
        self.cert_store.cert_slot(role).key_pair_id(cert_algo(algo))
    }

    fn cert_info(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u8> {
        let role = slot_role(slot)?;
        self.cert_store.cert_slot(role).cert_info(cert_algo(algo))
    }

    fn key_usage_mask(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u16> {
        let role = slot_role(slot)?;
        self.cert_store
            .cert_slot(role)
            .key_usage_mask(cert_algo(algo))
    }

    #[inline]
    fn cached_chain_digest(
        &self,
        slot: u8,
        asym_algo: SpdmPalAsymAlgo,
        _algo: SpdmPalHashAlgo,
    ) -> Option<[u8; 48]> {
        let role = slot_role(slot)?;
        self.cert_store
            .cached_chain_digest(role, cert_algo(asym_algo))
    }

    #[inline]
    fn cache_chain_digest(
        &self,
        slot: u8,
        asym_algo: SpdmPalAsymAlgo,
        _algo: SpdmPalHashAlgo,
        digest: &[u8],
    ) {
        if let Some(role) = slot_role(slot) {
            self.cert_store
                .cache_chain_digest(role, cert_algo(asym_algo), digest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_role_maps_vendor_owner_tenant() {
        assert_eq!(slot_role(0), Some(EndorsementRole::Vendor));
        assert_eq!(slot_role(2), Some(EndorsementRole::Owner));
        assert_eq!(slot_role(3), Some(EndorsementRole::Tenant));
        assert_eq!(slot_role(1), None);
        assert_eq!(slot_role(4), None);
    }

    #[cfg(feature = "set-certificate")]
    #[test]
    fn map_set_cert_error_translates_storage_and_cert_store_errors() {
        assert_eq!(
            map_set_cert_error(cert_errors::STORAGE_BUSY),
            caliptra_mcu_spdm_codec::errors::SPDM_BUSY
        );
        assert_eq!(
            map_set_cert_error(cert_errors::STORAGE_ERROR),
            caliptra_mcu_spdm_codec::errors::SPDM_OPERATION_FAILED
        );
        assert_eq!(
            map_set_cert_error(cert_errors::INVALID_ENDORSEMENT),
            caliptra_mcu_spdm_codec::errors::SPDM_INVALID_REQUEST
        );
        assert_eq!(
            map_set_cert_error(cert_errors::KEY_MISMATCH),
            caliptra_mcu_spdm_codec::errors::SPDM_INVALID_REQUEST
        );
    }
}
