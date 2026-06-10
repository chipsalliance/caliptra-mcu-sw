// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request dispatch for SPDM-Lite.

mod decode;
mod response;

use mcu_spdm_lite_codec::ReqRespCode;
use mcu_spdm_lite_traits::{PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport, SpdmVdmBackend};

use crate::build::build_error_response;
use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNSUPPORTED_REQUEST};
use crate::stack::ConnectionState;

pub(crate) async fn handle_vendor_defined_request<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    Vdm::Error: Into<crate::error::SpdmError>,
{
    if io.request().len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vdm_req =
        match decode::decode_vendor_defined_request::<Pal, Vdm>(state, io, io.request(), backend) {
            Ok(req) => req,
            Err(e) if e == SPDM_UNSUPPORTED_REQUEST => {
                return unsupported_request(pal, io, state.version)
            }
            Err(e) => return Err(e),
        };
    response::build_vendor_defined_response(state, pal, io, vdm_req, backend).await
}

pub(crate) async fn handle_large_vendor_defined_request<Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    io: &impl SpdmPalIo,
    req: &[u8],
    backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    Vdm::Error: Into<crate::error::SpdmError>,
{
    let vdm_req = decode::decode_vendor_defined_request::<Pal, Vdm>(state, io, req, backend)?;
    response::build_vendor_defined_response_into(state, vdm_req, backend, out).await
}

fn unsupported_request<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    version: mcu_spdm_lite_codec::SpdmVersion,
) -> SpdmResult<PalBytes<'a, Pal>> {
    build_error_response(
        pal,
        io,
        version,
        SPDM_UNSUPPORTED_REQUEST.spec_byte(),
        ReqRespCode::VENDOR_DEFINED_REQUEST.0,
        &[],
    )
}
