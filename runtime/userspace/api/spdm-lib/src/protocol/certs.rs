// Licensed under the Apache-2.0 license
use bitfield::bitfield;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub(crate) const SPDM_MAX_CERT_CHAIN_PORTION_LEN: u16 = 512;
pub(crate) const SPDM_CERT_CHAIN_METADATA_LEN: usize = size_of::<SpdmCertChainHeader>();

#[derive(IntoBytes, FromBytes, Immutable, Debug)]
#[repr(C, packed)]
pub(crate) struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
    pub root_hash: [u8; SHA384_HASH_SIZE],
}

impl Default for SpdmCertChainHeader {
    fn default() -> Self {
        Self {
            length: 0,
            reserved: 0,
            root_hash: [0u8; SHA384_HASH_SIZE],
        }
    }
}

// SPDM CertificateInfo fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C, packed)]
pub struct CertificateInfo(u8);
impl Debug;
u8;
pub cert_model, set_cert_model: 0,2;
reserved, _: 3,7;
}

// SPDM KeyUsageMask fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct KeyUsageMask(u16);
impl Debug;
u16;
pub key_exch_usage, set_key_exch_usage: 0,0;
pub challenge_usage, set_challenge_usage: 1,1;
pub measurement_usage, set_measurement_usage: 2,2;
pub endpoint_info_usage, set_endpoint_info_usage: 3,3;
reserved, _: 13,4;
pub standards_key_usage, set_standards_key_usage: 14,14;
pub vendor_key_usage, set_vendor_key_usage: 15,15;
}
