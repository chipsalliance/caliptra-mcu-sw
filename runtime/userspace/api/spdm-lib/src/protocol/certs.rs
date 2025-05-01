// Licensed under the Apache-2.0 license
use crate::protocol::SHA384_HASH_SIZE;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const SPDM_MAX_CERT_CHAIN_PORTION_LEN: u16 = 512;
pub const SPDM_CERT_CHAIN_METADATA_LEN: u16 =
    size_of::<SpdmCertChainHeader>() as u16 + SHA384_HASH_SIZE as u16;

pub type SupportedSlotMask = u8;
pub type ProvisionedSlotMask = u8;
pub type KeyPairID = u8;

#[derive(IntoBytes, FromBytes, Immutable)]
#[repr(packed)]
pub struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum SpdmCertModel {
    DeviceCertModel = 1,
    AliasCertModel = 2,
    GenericCertModel = 3,
}

// SPDM CertificateInfo fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone)]
#[repr(C, packed)]
pub struct CertificateInfo(u8);
impl Debug;
u8;
pub cert_model, set_cert_model: 0,2;
reserved, _: 3,7;
}

// SPDM KeyUsageMask fields
bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default, Clone)]
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
