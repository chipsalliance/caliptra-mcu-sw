// Licensed under the Apache-2.0 license

//! Host-side libspdm HAL stubs not provided by the pinned `spdm-utils` crate.
//!
//! `caliptra-spdm-emu`'s libspdm can reference newer optional responder HAL
//! callbacks even when the host tools only use requester flows. `spdm-utils`
//! already defines the older callback set; these no-op stubs fill only the
//! additional symbols needed to link the newer native archives.

use core::ffi::c_void;

const LIBSPDM_STATUS_UNSUPPORTED_CAP: u32 = 0x8001_0002;

#[no_mangle]
pub unsafe extern "C" fn libspdm_event_get_types(
    _spdm_context: *mut c_void,
    _spdm_version: u16,
    _session_id: u32,
    _supported_event_groups_list: *mut c_void,
    _supported_event_groups_list_len: *mut u32,
    _event_group_count: *mut u8,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_event_subscribe(
    _spdm_context: *mut c_void,
    _spdm_version: u16,
    _session_id: u32,
    _subscribe_type: u8,
    _subscribe_event_group_count: u8,
    _subscribe_list_len: u32,
    _subscribe_list: *const c_void,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_generate_event_list(
    _spdm_context: *mut c_void,
    _spdm_version: u16,
    _session_id: u32,
    _event_count: *mut u32,
    _events_list_size: *mut usize,
    _events_list: *mut c_void,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_generate_device_endpoint_info(
    _spdm_context: *mut c_void,
    _sub_code: u8,
    _request_attributes: u8,
    _endpoint_info_size: *mut u32,
    _endpoint_info: *mut c_void,
) -> u32 {
    LIBSPDM_STATUS_UNSUPPORTED_CAP
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_measurement_extension_log_collection(
    _spdm_context: *mut c_void,
    _mel_specification: u8,
    _measurement_specification: u8,
    _measurement_hash_algo: u32,
    _spdm_mel: *mut *mut c_void,
    _spdm_mel_size: *mut usize,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_read_total_key_pairs(_spdm_context: *mut c_void) -> u8 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_read_key_pair_info(
    _spdm_context: *mut c_void,
    _key_pair_id: u8,
    _capabilities: *mut u16,
    _key_usage_capabilities: *mut u16,
    _current_key_usage: *mut u16,
    _asym_algo_capabilities: *mut u32,
    _current_asym_algo: *mut u32,
    _pqc_asym_algo_capabilities: *mut u32,
    _current_pqc_asym_algo: *mut u32,
    _assoc_cert_slot_mask: *mut u8,
    _public_key_info_len: *mut u16,
    _public_key_info: *mut u8,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_write_key_pair_info(
    _spdm_context: *mut c_void,
    _key_pair_id: u8,
    _operation: u8,
    _desired_key_usage: u16,
    _desired_asym_algo: u32,
    _desired_pqc_asym_algo: u32,
    _desired_assoc_cert_slot_mask: u8,
    _need_reset: *mut bool,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_get_cert_chain_slot_storage_size(
    _spdm_context: *mut c_void,
    _slot_id: u8,
) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_challenge_start_mut_auth(
    _spdm_context: *mut c_void,
    _spdm_version: u16,
    _slot_id: u8,
    _request_context_size: usize,
    _request_context: *const c_void,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_key_exchange_rsp_opaque_data(
    _spdm_context: *mut c_void,
    _spdm_version: u16,
    _measurement_hash_type: u8,
    _slot_id: u8,
    _session_policy: u8,
    _req_opaque_data: *const c_void,
    _req_opaque_data_size: usize,
    _opaque_data: *mut c_void,
    _opaque_data_size: *mut usize,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_finish_rsp_opaque_data(
    _spdm_context: *mut c_void,
    _session_id: u32,
    _spdm_version: u16,
    _req_slot_id: u8,
    _req_opaque_data: *const c_void,
    _req_opaque_data_size: usize,
    _opaque_data: *mut c_void,
    _opaque_data_size: *mut usize,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_key_exchange_start_mut_auth(
    _spdm_context: *mut c_void,
    _session_id: u32,
    _spdm_version: u16,
    _slot_id: u8,
    _req_slot_id: *mut u8,
    _session_policy: u8,
    _opaque_data_length: usize,
    _opaque_data: *const c_void,
    _mandatory_mut_auth: *mut bool,
) -> u8 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_psk_exchange_rsp_opaque_data(
    _spdm_context: *mut c_void,
    _psk_hint: *const c_void,
    _psk_hint_size: u16,
    _spdm_version: u16,
    _measurement_hash_type: u8,
    _req_opaque_data: *const c_void,
    _req_opaque_data_size: usize,
    _opaque_data: *mut c_void,
    _opaque_data_size: *mut usize,
) -> bool {
    false
}

#[no_mangle]
pub unsafe extern "C" fn libspdm_psk_finish_rsp_opaque_data(
    _spdm_context: *mut c_void,
    _session_id: u32,
    _spdm_version: u16,
    _req_opaque_data: *const c_void,
    _req_opaque_data_size: usize,
    _opaque_data: *mut c_void,
    _opaque_data_size: *mut usize,
) -> bool {
    false
}
