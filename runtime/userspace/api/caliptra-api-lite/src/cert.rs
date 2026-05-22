// Licensed under the Apache-2.0 license

//! Miscellaneous certificate mailbox commands.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{calc_checksum, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

/// Caliptra command ID for `POPULATE_IDEV_ECC384_CERT`.
const CMD_POPULATE_IDEV_ECC384_CERT: u32 = 0x4944_4550; // "IDEP"

/// Maximum IDevID cert size accepted by Caliptra.
const POPULATE_IDEV_MAX_CERT_SIZE: usize = 1024;

/// Request prefix: `chksum(4) + cert_size(4)`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct PopulateIdevReqPrefix {
    chksum: U32,
    cert_size: U32,
}

const PREFIX_LEN: usize = core::mem::size_of::<PopulateIdevReqPrefix>();
const _: () = assert!(PREFIX_LEN == 8);

/// Populate the signed IDevID ECC-384 certificate into Caliptra via
/// the `POPULATE_IDEV_ECC384_CERT` mailbox command.
#[inline(never)]
pub async fn populate_idev_ecc384_cert<A: ApiAlloc>(alloc: &A, cert: &[u8]) -> McuResult<()> {
    if cert.is_empty() || cert.len() > POPULATE_IDEV_MAX_CERT_SIZE {
        return Err(INVARIANT);
    }

    let req_len = PREFIX_LEN + POPULATE_IDEV_MAX_CERT_SIZE;
    let mut req = alloc.alloc(req_len)?;
    req.fill(0);

    {
        let prefix =
            PopulateIdevReqPrefix::mut_from_bytes(&mut req[..PREFIX_LEN]).map_err(|_| INVARIANT)?;
        prefix.cert_size = U32::new(cert.len() as u32);
    }
    req[PREFIX_LEN..PREFIX_LEN + cert.len()].copy_from_slice(cert);
    let checksum = calc_checksum(CMD_POPULATE_IDEV_ECC384_CERT, &req);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let _rsp_len = crate::wire::mbox_execute(CMD_POPULATE_IDEV_ECC384_CERT, &req, &mut rsp).await?;

    Ok(())
}
