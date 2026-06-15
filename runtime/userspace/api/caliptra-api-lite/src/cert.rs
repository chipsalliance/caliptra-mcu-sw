// Licensed under the Apache-2.0 license

//! Miscellaneous certificate mailbox commands.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    calc_checksum, CMD_GET_ATTESTED_ECC384_CSR, CMD_GET_ATTESTED_MLDSA87_CSR, MBOX_RESP_HEADER_SIZE,
};
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

// ---------------------------------------------------------------------------
// GET_ATTESTED_*_CSR — alloc-backed, in-place response handling
// ---------------------------------------------------------------------------

/// `GET_ATTESTED_*_CSR` request size on the wire:
/// `chksum(4) | key_id(4) | nonce(32)` = 40 B.
const ATTESTED_CSR_REQ_LEN: usize = 40;

/// Bytes preceding the CSR data in the mailbox response:
/// `MailboxRespHeader(8) | data_size(4)` = 12 B.
const ATTESTED_CSR_RSP_PREFIX_LEN: usize = MBOX_RESP_HEADER_SIZE + 4;

/// Issue `GET_ATTESTED_ECC384_CSR` and write the returned CSR DER bytes into
/// `csr_out`, returning the number of bytes written.
///
/// `csr_out` is also used as the mailbox response buffer for the duration of
/// the call; on return, only the CSR data occupies its prefix. The caller must
/// provide a `csr_out` of at least [`ATTESTED_CSR_RSP_PREFIX_LEN`] bytes plus
/// the expected CSR size.
#[inline(never)]
pub async fn get_attested_csr_ecc384(
    key_id: u32,
    nonce: &[u8; 32],
    csr_out: &mut [u8],
) -> McuResult<usize> {
    get_attested_csr_inner(CMD_GET_ATTESTED_ECC384_CSR, key_id, nonce, csr_out).await
}

/// Issue `GET_ATTESTED_MLDSA87_CSR` and write the returned CSR DER bytes into
/// `csr_out`. See [`get_attested_csr_ecc384`] for buffer semantics.
#[inline(never)]
pub async fn get_attested_csr_mldsa87(
    key_id: u32,
    nonce: &[u8; 32],
    csr_out: &mut [u8],
) -> McuResult<usize> {
    get_attested_csr_inner(CMD_GET_ATTESTED_MLDSA87_CSR, key_id, nonce, csr_out).await
}

async fn get_attested_csr_inner(
    cmd: u32,
    key_id: u32,
    nonce: &[u8; 32],
    csr_out: &mut [u8],
) -> McuResult<usize> {
    if csr_out.len() <= ATTESTED_CSR_RSP_PREFIX_LEN {
        return Err(INVARIANT);
    }

    // Build the 40-byte request on the stack (small enough to not bloat the
    // async future captured by an embassy task; the prior approach held a
    // 12,812-byte AttestedCsrResp across `.await`, which we explicitly avoid).
    let mut req = [0u8; ATTESTED_CSR_REQ_LEN];
    req[4..8].copy_from_slice(&key_id.to_le_bytes());
    req[8..ATTESTED_CSR_REQ_LEN].copy_from_slice(nonce);
    let checksum = calc_checksum(cmd, &req[4..]);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    // Use the caller's buffer as the mailbox response buffer; afterwards
    // memmove the CSR data over the response prefix.
    let actual = crate::wire::mbox_execute(cmd, &req, csr_out).await?;
    if actual < ATTESTED_CSR_RSP_PREFIX_LEN {
        return Err(INVARIANT);
    }
    let data_size = u32::from_le_bytes([csr_out[8], csr_out[9], csr_out[10], csr_out[11]]) as usize;
    if data_size == 0
        || data_size > csr_out.len() - ATTESTED_CSR_RSP_PREFIX_LEN
        || ATTESTED_CSR_RSP_PREFIX_LEN + data_size > actual
    {
        return Err(INVARIANT);
    }
    csr_out.copy_within(
        ATTESTED_CSR_RSP_PREFIX_LEN..ATTESTED_CSR_RSP_PREFIX_LEN + data_size,
        0,
    );
    Ok(data_size)
}
