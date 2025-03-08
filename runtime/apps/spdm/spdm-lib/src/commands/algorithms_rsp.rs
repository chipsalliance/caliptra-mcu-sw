// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, DataKind, MessageBuf};
use crate::commands::error_rsp::ErrorCode;
use crate::context::SpdmContext;
use crate::error::{CommandResult, SpdmError};
use crate::protocol::algorithms::*;
use crate::protocol::capabilities::*;
use crate::protocol::common::SpdmMsgHdr;
use crate::protocol::SpdmVersion;
use crate::state::ConnectionState;
use bitfield::bitfield;
use libtock_platform::Syscalls;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use core::fmt::Write;

// Max request length shall be 128 bytes (SPDM1.3 10.4, Table 10.4)
const MAX_REQUEST_LENGTH: u16 = 128;
const MAX_SPDM_EXT_ALG_COUNT_V10: u8 = 8;
const MAX_SPDM_EXT_ALG_COUNT_V11: u8 = 20;

#[derive(IntoBytes, FromBytes, Immutable, Default, Debug)]
#[repr(packed)]
struct NegotiateAlgorithmsReq {
    num_alg_struct_tables: u8,
    reserved_1: u8,
    length: u16,
    measurement_specification: MeasurementSpecification,
    other_param_support: OtherParamSupport,
    base_asym_algo: BaseAsymAlgo,
    base_hash_algo: BaseHashAlgo,
    reserved_2: [u8; 12],
    ext_asyn_count: u8,
    ext_hash_count: u8,
    reserved_3: u8,
    mel_specification: MelSpecification,
}

impl NegotiateAlgorithmsReq {
    fn min_req_len(&self) -> u16 {
        let total_alg_struct_len =
            core::mem::size_of::<AlgStructure>() * self.num_alg_struct_tables as usize;
        let total_ext_asym_len =
            core::mem::size_of::<ExtendedAlgo>() * self.ext_asyn_count as usize;
        let total_ext_hash_len =
            core::mem::size_of::<ExtendedAlgo>() * self.ext_hash_count as usize;
        (core::mem::size_of::<NegotiateAlgorithmsReq>()
            + total_alg_struct_len
            + total_ext_asym_len
            + total_ext_hash_len) as u16
    }

    fn ext_algo_size(&self) -> usize {
        let ext_algo_count = self.ext_asyn_count as usize + self.ext_hash_count as usize;
        core::mem::size_of::<ExtendedAlgo>() * ext_algo_count
    }

    fn validate_total_ext_alg_count(
        &self,
        version: SpdmVersion,
        total_ext_alg_count: u8,
    ) -> Result<(), SpdmError> {
        let max_count = match version {
            SpdmVersion::V10 => MAX_SPDM_EXT_ALG_COUNT_V10,
            _ => MAX_SPDM_EXT_ALG_COUNT_V11,
        };

        if total_ext_alg_count > max_count {
            Err(SpdmError::InvalidParam)
        } else {
            Ok(())
        }
    }
}

impl CommonCodec for NegotiateAlgorithmsReq {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(packed)]
struct NegotiateAlgorithmsResp {
    num_alg_struct_tables: u8,
    reserved_1: u8,
    length: u16,
    measurement_specification_sel: MeasurementSpecification,
    other_params_selection: OtherParamSupport,
    measurement_hash_algo: MeasurementHashAlgo,
    base_asym_sel: BaseAsymAlgo,
    base_hash_sel: BaseHashAlgo,
    reserved_2: [u8; 11],
    mel_specification_sel: MelSpecification,
    ext_asym_sel_count: u8,
    ext_hash_sel_count: u8,
    reserved_3: [u8; 2],
}

impl CommonCodec for NegotiateAlgorithmsResp {
    const DATA_KIND: DataKind = DataKind::Payload;
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
struct ExtendedAlgo {
    registry_id: u8,
    reserved: u8,
    algorithm_id: u16,
}

impl CommonCodec for ExtendedAlgo {
    const DATA_KIND: DataKind = DataKind::Payload;
}

enum AlgType {
    Dhe = 2,
    AeadCipherSuite = 3,
    ReqBaseAsymAlg = 4,
    KeySchedule = 5,
}
impl TryFrom<u8> for AlgType {
    type Error = SpdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(AlgType::Dhe),
            3 => Ok(AlgType::AeadCipherSuite),
            4 => Ok(AlgType::ReqBaseAsymAlg),
            5 => Ok(AlgType::KeySchedule),
            _ => Err(SpdmError::InvalidParam),
        }
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
    #[repr(C)]
    pub struct AlgStructure(u32);
    impl Debug;
    u8;
        pub alg_type, set_alg_type: 7, 0;
        pub fixed_alg_size, set_fixed_alg_size: 11, 8;
        pub ext_alg_count, set_ext_alg_count: 15, 12;
    u16;
        pub alg_supported, set_alg_supported: 31, 16;
}

impl CommonCodec for AlgStructure {
    const DATA_KIND: DataKind = DataKind::Payload;
}

fn process_negotiate_algorithms_request<S: Syscalls>(
    ctx: &mut SpdmContext<S>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf,
) -> CommandResult<()> {
    // Validate the version
    let connection_version = ctx.state.connection_info.version_number();
    match spdm_hdr.version() {
        Ok(version) if version == connection_version => {}
        _ => {
            return Err(ctx.generate_error_response(
                req_payload,
                ErrorCode::VersionMismatch,
                0,
                None,
            ))
        }
    }

    let req_start_offset = req_payload.data_offset() - core::mem::size_of::<SpdmMsgHdr>();
    writeln!(ctx.cw, "SPDM_LIB: Data offset: {}", req_start_offset).unwrap();

    let req = NegotiateAlgorithmsReq::decode(req_payload).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;

    writeln!(ctx.cw, "SPDM_LIB: Req {:?}", req).unwrap();

    // check req length
    if req.length > MAX_REQUEST_LENGTH || req.length < req.min_req_len() as u16 {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }

    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    // Check other parameters
    let other_params_support = req.other_param_support;
    if other_params_support.reserved1() != 0 || other_params_support.reserved2() != 0 {
        return Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None));
    }
    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    // Extended Asym and Hash Algo size
    let ext_algo_size = req.ext_algo_size();

    // Responder doesn't support any extended asym or hash algorithms. No need to process the extended algorithms.
    req_payload.pull_data(ext_algo_size as usize).map_err(|_| {
        ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
    })?;
    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    let mut prev_alg_type = 0;
    let mut total_ext_alg_count = 0;
    let mut dhe_name_group = DheNamedGroup::default();
    let mut aead_cipher_suite = AeadCipherSuite::default();
    let mut req_base_asym_alg = ReqBaseAsymAlg::default();
    let mut key_schedule = KeySchedule::default();

    for i in 0..req.num_alg_struct_tables as usize {
        let alg_struct = AlgStructure::decode(req_payload).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

        let alg_type = AlgType::try_from(alg_struct.alg_type()).map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

        // AlgType shall monotonically increase
        if i > 0 && prev_alg_type > alg_struct.alg_type() {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

        prev_alg_type = alg_struct.alg_type();

        // Process fixed algorithms supported by Requester for the alg_type
        if alg_struct.alg_supported() == 0 {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

        match alg_type {
            AlgType::Dhe => dhe_name_group = DheNamedGroup(alg_struct.alg_supported()),
            AlgType::AeadCipherSuite => {
                aead_cipher_suite = AeadCipherSuite(alg_struct.alg_supported())
            }
            AlgType::ReqBaseAsymAlg => {
                req_base_asym_alg = ReqBaseAsymAlg(alg_struct.alg_supported())
            }
            AlgType::KeySchedule => key_schedule = KeySchedule(alg_struct.alg_supported()),
        }

        // Process extended algorithms supported by Requester
        let ext_alg_count = alg_struct.ext_alg_count();
        total_ext_alg_count += ext_alg_count;

        let fixed_alg_size = alg_struct.fixed_alg_size();
        if fixed_alg_size != 2 {
            Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
        }
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

        req_payload
            .pull_data(fixed_alg_size as usize)
            .map_err(|_| {
                ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
            })?;
        writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();
    }

    // Check the total number of extended algorithms
    req.validate_total_ext_alg_count(connection_version, total_ext_alg_count)
        .map_err(|_| {
            ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None)
        })?;
    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    writeln!(
        ctx.cw,
        "SPDM_LIB: current data offset {} start offset {}",
        req_payload.data_offset(),
        req_start_offset
    )
    .unwrap();

    // Check total length of the request
    let req_len = req_payload.data_offset() - req_start_offset;
    if req_len != req.length as usize {
        Err(ctx.generate_error_response(req_payload, ErrorCode::InvalidRequest, 0, None))?;
    }
    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    let measurement_hash_algo = if req.measurement_specification.dmtf_measurement_spec() == 0 {
        MeasurementHashAlgo::default()
    } else {
        ctx.local_algorithms.device_algorithms.measurement_hash_algo
    };

    let peer_algorithms = DeviceAlgorithms {
        measurement_spec: req.measurement_specification,
        other_param_support: req.other_param_support,
        measurement_hash_algo,
        base_asym_algo: req.base_asym_algo,
        base_hash_algo: req.base_hash_algo,
        mel_specification: req.mel_specification,
        dhe_group: dhe_name_group,
        aead_cipher_suite: aead_cipher_suite,
        req_base_asym_algo: req_base_asym_alg,
        key_schedule: key_schedule,
    };
    writeln!(ctx.cw, "SPDM_LIB: {}", line!()).unwrap();

    ctx.state
        .connection_info
        .set_peer_algorithms(peer_algorithms);
    writeln!(
        ctx.cw,
        "SPDM_LIB: Processed request. Peer algorithms: {:?}",
        peer_algorithms
    )
    .unwrap();
    Ok(())
}

fn generate_algorithms_response<S: Syscalls>(
    ctx: &mut SpdmContext<S>,
    rsp: &mut MessageBuf,
) -> CommandResult<()> {
    let connection_version = ctx.state.connection_info.version_number();
    let peer_algorithms = ctx.state.connection_info.peer_algorithms();
    let local_algorithms = &ctx.local_algorithms.device_algorithms;
    let algorithm_priority_table = &ctx.local_algorithms.algorithm_priority_table;
    let local_cap_flags = &ctx.local_capabilities.flags;

    let num_alg_struct_tables = peer_algorithms.num_alg_struct_tables();

    // No extended asymmetric key and hash algorithms response.
    let rsp_length = core::mem::size_of::<NegotiateAlgorithmsResp>()
        + num_alg_struct_tables * core::mem::size_of::<AlgStructure>();

    // MeasurementSpecificationSel
    let mut measurement_specification_sel = MeasurementSpecification::default();
    if local_cap_flags.mel_cap() == 1
        || (local_cap_flags.meas_cap() == MeasCapability::MeasurementsWithNoSignature as u8
            || local_cap_flags.meas_cap() == MeasCapability::MeasurementsWithSignature as u8)
    {
        measurement_specification_sel = local_algorithms.measurement_spec.prioritize(
            peer_algorithms.measurement_spec,
            algorithm_priority_table.measurement_specification,
        );
    }

    // OtherParamsSelection (Responder doesn't set the multi asymmetric key use flag)
    let mut other_params_selection = OtherParamSupport::default();
    if connection_version >= SpdmVersion::V12 {
        other_params_selection = local_algorithms.other_param_support.prioritize(
            peer_algorithms.other_param_support,
            algorithm_priority_table.opaque_data_format,
        );
    }

    // MeasurementHashAlgo
    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    if local_cap_flags.meas_cap() == MeasCapability::MeasurementsWithNoSignature as u8
        || local_cap_flags.meas_cap() == MeasCapability::MeasurementsWithSignature as u8
    {
        measurement_hash_algo = local_algorithms.measurement_hash_algo;
    }

    // BaseAsymSel
    let base_asym_sel = local_algorithms.base_asym_algo.prioritize(
        peer_algorithms.base_asym_algo,
        algorithm_priority_table.base_asym_algo,
    );

    // BaseHashSel
    let base_hash_sel = local_algorithms.base_hash_algo.prioritize(
        peer_algorithms.base_hash_algo,
        algorithm_priority_table.base_hash_algo,
    );

    // MelSpecificationSel
    let mel_specification_sel = local_algorithms.mel_specification.prioritize(
        peer_algorithms.mel_specification,
        algorithm_priority_table.mel_specification,
    );

    let algorithms_rsp = NegotiateAlgorithmsResp {
        num_alg_struct_tables: num_alg_struct_tables as u8,
        reserved_1: 0,
        length: rsp_length as u16,
        measurement_specification_sel,
        other_params_selection,
        measurement_hash_algo,
        base_asym_sel,
        base_hash_sel,
        reserved_2: [0; 11],
        mel_specification_sel,
        ext_asym_sel_count: 0,
        ext_hash_sel_count: 0,
        reserved_3: [0; 2],
    };

    // Fill the response buffer with fixed algorithms response fields
    let mut len = algorithms_rsp
        .encode(rsp)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

    // Fill the response buffer with algorithm response structures
    len += fill_alg_struct_table(ctx, rsp, num_alg_struct_tables)?;

    rsp.push_data(len)
        .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
    // writeln!(
    //     ctx.cw,
    //     "SPDM_LIB: Algorithms response Completed. length: {}",
    //     rsp.data_offset()
    // )
    // .unwrap();

    Ok(())
}

fn fill_alg_struct_table<S: Syscalls>(
    ctx: &mut SpdmContext<S>,
    rsp: &mut MessageBuf,
    num_alg_struct_tables: usize,
) -> CommandResult<usize> {
    let mut i = 0;
    let local_algorithms = &ctx.local_algorithms.device_algorithms;
    let peer_algorithms = ctx.state.connection_info.peer_algorithms();
    let algorithm_priority_table = &ctx.local_algorithms.algorithm_priority_table;
    let mut len = 0;

    // DheNameGroup
    if peer_algorithms.dhe_group.0 != 0 {
        let mut dhe_alg_struct = AlgStructure::default();
        dhe_alg_struct.set_alg_type(AlgType::Dhe as u8);
        dhe_alg_struct.set_fixed_alg_size(2);
        dhe_alg_struct.set_ext_alg_count(0);
        let dhe_alg_supported = local_algorithms.dhe_group.prioritize(
            peer_algorithms.dhe_group,
            algorithm_priority_table.dhe_group,
        );
        dhe_alg_struct.set_alg_supported(dhe_alg_supported.0);

        len += dhe_alg_struct
            .encode(rsp)
            .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        i += 1;
    }

    // AeadCipherSuite
    if peer_algorithms.aead_cipher_suite.0 != 0 {
        let mut aead_alg_struct = AlgStructure::default();
        aead_alg_struct.set_alg_type(AlgType::AeadCipherSuite as u8);
        aead_alg_struct.set_fixed_alg_size(2);
        aead_alg_struct.set_ext_alg_count(0);

        let aead_cipher_suite = local_algorithms.aead_cipher_suite.prioritize(
            peer_algorithms.aead_cipher_suite,
            algorithm_priority_table.aead_cipher_suite,
        );
        aead_alg_struct.set_alg_supported(aead_cipher_suite.0);

        len += aead_alg_struct
            .encode(rsp)
            .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        i += 1;
    }

    if peer_algorithms.req_base_asym_algo.0 != 0 {
        let mut req_base_asym_struct = AlgStructure::default();
        req_base_asym_struct.set_alg_type(AlgType::ReqBaseAsymAlg as u8);
        req_base_asym_struct.set_fixed_alg_size(2);
        req_base_asym_struct.set_ext_alg_count(0);

        let req_base_asym_algo = local_algorithms.req_base_asym_algo.prioritize(
            peer_algorithms.req_base_asym_algo,
            algorithm_priority_table.req_base_asym_algo,
        );
        req_base_asym_struct.set_alg_supported(req_base_asym_algo.0);
        len += req_base_asym_struct
            .encode(rsp)
            .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
        i += 1;
    }

    if peer_algorithms.key_schedule.0 != 0 {
        let mut key_schedule_struct = AlgStructure::default();
        key_schedule_struct.set_alg_type(AlgType::KeySchedule as u8);
        key_schedule_struct.set_fixed_alg_size(2);
        key_schedule_struct.set_ext_alg_count(0);
        let key_schedule = local_algorithms.key_schedule.prioritize(
            peer_algorithms.key_schedule,
            algorithm_priority_table.key_schedule,
        );
        key_schedule_struct.set_alg_supported(key_schedule.0);
        len += key_schedule_struct
            .encode(rsp)
            .map_err(|_| ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;

        i += 1;
    }

    // Check the number of algorithm structures
    if i != num_alg_struct_tables {
        Err(ctx.generate_error_response(rsp, ErrorCode::InvalidRequest, 0, None))?;
    }

    Ok(len)
}

pub(crate) fn handle_negotiate_algorithms<'a, S: Syscalls>(
    ctx: &mut SpdmContext<'a, S>,
    spdm_hdr: SpdmMsgHdr,
    req_payload: &mut MessageBuf<'a>,
) -> CommandResult<()> {
    writeln!(
        ctx.cw,
        "SPDM_LIB: Handle negotiate algorithms request. connection_state {:?}",
        ctx.state.connection_info.state()
    )
    .unwrap();
    // Validate the state
    if ctx.state.connection_info.state() != ConnectionState::AfterCapabilities {
        Err(ctx.generate_error_response(req_payload, ErrorCode::UnexpectedRequest, 0, None))?;
    }
    writeln!(ctx.cw, "SPDM_LIB: Processing request").unwrap();

    // process negotiate algorithms request
    process_negotiate_algorithms_request(ctx, spdm_hdr, req_payload)?;

    // generate algorithms response
    ctx.prepare_response_buffer(req_payload)?;
    generate_algorithms_response(ctx, req_payload)?;

    Ok(())
}
