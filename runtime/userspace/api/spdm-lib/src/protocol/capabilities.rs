// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_MCTP_SPDM_MSG_SIZE: usize = 2048;

pub const MIN_DATA_TRANSFER_SIZE_V12: u32 = 42;

// Maximum Cryptographic processing timeout to be reported in Capabilities response
pub const MAX_CT_EXPONENT: u8 = 31;

/// Measurements Capability
#[derive(Debug, Clone, Copy)]
pub enum MeasCapability {
    NoMeasurement = 0,
    MeasurementsWithNoSignature = 1,
    MeasurementsWithSignature = 2,
    Reserved = 3,
}

/// Pre-shared Key(PSK) Capability
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PskCapability {
    // PSK capability not supported
    NoPsk = 0,
    // PSK capability supported without session key derivation
    PskWithNoContext = 1,
    // PSK capability supported with session key derivation (reserved for requestor)
    PskWithContext = 2,
    // Reserved
    Reserved = 3,
}

/// Endpoint Information Capability
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum EpInfoCapability {
    NoEpInfo = 0,
    EpInfoWithNoSignature = 1,
    EpInfoWithSignature = 2,
    Reserved = 3,
}

/// Device Capabilities
#[derive(Default, Debug, Clone, Copy)]
pub struct DeviceCapabilities {
    pub ct_exponent: u8,
    pub flags: CapabilityFlags,
    // Only used for >= SPDM 1.2
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Clone, Copy)]
#[repr(C)]
pub struct CapabilityFlags(u32);
impl Debug;
u8;
pub cache_cap, set_cache_cap: 0, 0;
pub cert_cap, set_cert_cap: 1, 1;
pub chal_cap, set_chal_cap: 2, 2;
pub meas_cap, set_meas_cap: 4, 3;
pub meas_fresh_cap, set_meas_fresh_cap: 5, 5;
pub encrypt_cap, set_encrypt_cap: 6, 6;
pub mac_cap, set_mac_cap: 7, 7;
pub mut_auth_cap, set_mut_auth_cap: 8, 8;
pub key_ex_cap, set_key_ex_cap: 9, 9;
pub psk_cap, set_psk_cap: 11, 10;
pub encap_cap, set_encap_cap: 12, 12;
pub hbeat_cap, set_hbeat_cap: 13, 13;
pub key_upd_cap, set_key_upd_cap: 14, 14;
pub handshake_in_the_clear_cap, set_handshake_in_the_clear_cap: 15, 15;
pub pub_key_id_cap, set_pub_key_id_cap: 16, 16;
pub chunk_cap, set_chunk_cap: 17, 17;
pub alias_cert_cap, set_alias_cert_cap: 18, 18;
pub set_certificate_cap, set_set_certificate_cap: 19, 19;
pub csr_cap, set_csr_cap: 20, 20;
pub cert_install_reset_cap, set_cert_install_reset_cap: 21, 21;
pub ep_info_cap, set_ep_info_cap: 23, 22;
pub mel_cap, set_mel_cap: 24, 24;
pub event_cap, set_event_cap: 25, 25;
pub multi_key_cap, set_multi_key_cap: 27, 26;
pub get_key_pair_info_cap, set_get_key_pair_info_cap: 28, 28;
pub set_key_pair_info_cap, set_set_key_pair_info_cap: 29, 29;
reserved , _: 31, 30;
}

impl CapabilityFlags {
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }
}

impl Default for CapabilityFlags {
    fn default() -> Self {
        let mut capability_flags = CapabilityFlags::new(0);
        capability_flags.set_cache_cap(0);
        capability_flags.set_cert_cap(1);
        capability_flags.set_chal_cap(1);
        capability_flags.set_meas_cap(MeasCapability::MeasurementsWithSignature as u8);
        capability_flags.set_meas_fresh_cap(0);
        capability_flags.set_encrypt_cap(0);
        capability_flags.set_mac_cap(0);
        capability_flags.set_mut_auth_cap(0);
        capability_flags.set_key_ex_cap(0);
        capability_flags.set_psk_cap(PskCapability::NoPsk as u8);
        capability_flags.set_encap_cap(0);
        capability_flags.set_hbeat_cap(0);
        capability_flags.set_key_upd_cap(0);
        capability_flags.set_handshake_in_the_clear_cap(0);
        capability_flags.set_pub_key_id_cap(0);
        capability_flags.set_chunk_cap(1);
        capability_flags.set_alias_cert_cap(1);

        capability_flags
    }
}
