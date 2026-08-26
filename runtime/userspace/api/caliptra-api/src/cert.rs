// Licensed under the Apache-2.0 license

//! Miscellaneous certificate mailbox commands.

use caliptra_api::mailbox::{PopulateIdevEcc384CertReq, PopulateIdevMldsa87CertReq};
use core::mem::{offset_of, size_of};
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    calc_checksum, CMD_GET_ATTESTED_ECC384_CSR, CMD_GET_ATTESTED_MLDSA87_CSR,
    CMD_GET_IDEV_ECC384_CSR, CMD_POPULATE_IDEV_MLDSA87_CERT, MBOX_RESP_HEADER_SIZE,
};
use crate::ApiAlloc;

/// Caliptra command ID for `POPULATE_IDEV_ECC384_CERT`.
const CMD_POPULATE_IDEV_ECC384_CERT: u32 = 0x4944_4550; // "IDEP"

/// Maximum IDevID ECC-384 cert size accepted by Caliptra
/// (`PopulateIdevEcc384CertReq::MAX_CERT_SIZE`).
pub const POPULATE_IDEV_ECC384_MAX_CERT_SIZE: usize = 1024;

/// Fixed-size head of a `POPULATE_IDEV_*_CERT` request:
/// `MailboxReqHeader.chksum(4) | cert_size(4)`, followed on the wire by exactly
/// `cert_size` certificate bytes.
///
/// `Unaligned` with `little_endian::U32` fields on purpose: this is written
/// directly into an allocator-provided byte buffer, so no field may assume host
/// alignment or host endianness. Both `POPULATE_IDEV_ECC384_CERT` and
/// `POPULATE_IDEV_MLDSA87_CERT` share this head; only the cert cap differs.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct PopulateIdevCertReqHeader {
    chksum: U32,
    cert_size: U32,
}

const PREFIX_LEN: usize = size_of::<PopulateIdevCertReqHeader>();
const _: () = assert!(PREFIX_LEN == 8);

// The wire layout is anchored to Caliptra's own request structs rather than to
// hand-counted offsets, so a change on the Caliptra side breaks the build here
// instead of producing a request Caliptra silently rejects.
//
// `size_of` / `offset_of` / associated consts are const-evaluated, so naming the
// 8,200-byte `PopulateIdevMldsa87CertReq` costs no code, no `.bss` and no stack:
// the type is never instantiated in this crate. Keeping the large request
// structs out of the *values* this crate handles is the whole reason the header
// is built by hand instead of via `PopulateIdevMldsa87CertReq::default()`.
const _: () = assert!(offset_of!(PopulateIdevMldsa87CertReq, hdr) == 0);
const _: () = assert!(
    offset_of!(PopulateIdevMldsa87CertReq, cert_size)
        == offset_of!(PopulateIdevCertReqHeader, cert_size)
);
const _: () = assert!(offset_of!(PopulateIdevMldsa87CertReq, cert) == PREFIX_LEN);
const _: () =
    assert!(POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE == PopulateIdevMldsa87CertReq::MAX_CERT_SIZE);
const _: () = assert!(
    PREFIX_LEN + POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE == size_of::<PopulateIdevMldsa87CertReq>()
);

const _: () = assert!(offset_of!(PopulateIdevEcc384CertReq, hdr) == 0);
const _: () = assert!(
    offset_of!(PopulateIdevEcc384CertReq, cert_size)
        == offset_of!(PopulateIdevCertReqHeader, cert_size)
);
const _: () = assert!(offset_of!(PopulateIdevEcc384CertReq, cert) == PREFIX_LEN);
const _: () =
    assert!(POPULATE_IDEV_ECC384_MAX_CERT_SIZE == PopulateIdevEcc384CertReq::MAX_CERT_SIZE);
const _: () = assert!(
    PREFIX_LEN + POPULATE_IDEV_ECC384_MAX_CERT_SIZE == size_of::<PopulateIdevEcc384CertReq>()
);

/// Populate the signed IDevID ECC-384 certificate into Caliptra via
/// the `POPULATE_IDEV_ECC384_CERT` mailbox command.
#[inline(never)]
pub async fn populate_idev_ecc384_cert<A: ApiAlloc>(alloc: &A, cert: &[u8]) -> McuResult<()> {
    if cert.is_empty() || cert.len() > POPULATE_IDEV_ECC384_MAX_CERT_SIZE {
        return Err(INVARIANT);
    }

    let req_len = PREFIX_LEN + POPULATE_IDEV_ECC384_MAX_CERT_SIZE;
    let mut req = alloc.alloc(req_len)?;
    req.fill(0);

    {
        let prefix = PopulateIdevCertReqHeader::mut_from_bytes(&mut req[..PREFIX_LEN])
            .map_err(|_| INVARIANT)?;
        prefix.cert_size = U32::new(cert.len() as u32);
    }
    req[PREFIX_LEN..PREFIX_LEN + cert.len()].copy_from_slice(cert);
    let checksum = calc_checksum(CMD_POPULATE_IDEV_ECC384_CERT, &req);
    req[..4].copy_from_slice(&checksum.to_le_bytes());

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let _rsp_len = crate::wire::mbox_execute(CMD_POPULATE_IDEV_ECC384_CERT, &req, &mut rsp).await?;

    Ok(())
}

/// Maximum IDevID ML-DSA-87 cert size accepted by Caliptra
/// (`PopulateIdevMldsa87CertReq::MAX_CERT_SIZE`).
pub const POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE: usize = 8192;

/// Length of an IDevID certificate held in an OTP partition, decided from the
/// partition's first word.
///
/// A certificate is an ASN.1 SEQUENCE: tag `0x30` then a long-form length.
/// `0x82` (2 length bytes) is the only form these certs can take — both exceed
/// 127 bytes, and Caliptra's 8192-byte cap rules out `0x83`.
///
/// Returns `None` for anything not installable: erased OTP (which reads back
/// `0xFF`), a non-SEQUENCE tag, a zero body, or a length overrunning the
/// partition or `max_cert_size`. Bounding by the *partition* matters because an
/// OTP read clamps a straddling word to the partition end and pads with `0xFF`,
/// so an over-long length would splice fill into the attestation chain.
///
/// `header_word` is the first 4 bytes of the partition, little-endian.
pub fn cert_der_len(
    header_word: u32,
    partition_size: usize,
    max_cert_size: usize,
) -> Option<usize> {
    let b = header_word.to_le_bytes();
    if b[0] != 0x30 || b[1] != 0x82 {
        return None;
    }
    let body_len = ((b[2] as usize) << 8) | (b[3] as usize);
    if body_len == 0 {
        return None;
    }
    // 4 header bytes (tag + 0x82 + 2 length bytes) precede the body.
    let total = body_len + 4;
    if total > partition_size || total > max_cert_size {
        return None;
    }
    Some(total)
}

/// [`cert_der_len`] with Caliptra's ECC-384 cap applied.
pub fn ecc384_cert_der_len(header_word: u32, partition_size: usize) -> Option<usize> {
    cert_der_len(
        header_word,
        partition_size,
        POPULATE_IDEV_ECC384_MAX_CERT_SIZE,
    )
}

/// [`cert_der_len`] with Caliptra's ML-DSA-87 cap applied.
pub fn mldsa87_cert_der_len(header_word: u32, partition_size: usize) -> Option<usize> {
    cert_der_len(
        header_word,
        partition_size,
        POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE,
    )
}

/// Populate the signed IDevID ML-DSA-87 certificate into Caliptra via the
/// `POPULATE_IDEV_MLDSA87_CERT` mailbox command.
///
/// `cert` is the exact DER bytes to submit. It is sent as one contiguous payload
/// rather than streamed: the mailbox lock is taken before a stream is pulled
/// from, so streaming out of a slow backing store (e.g. OTP, 4 bytes per
/// syscall) would hold the Caliptra mailbox with EXECUTE asserted long enough to
/// starve other mailbox users. The caller stages the certificate first.
#[inline(never)]
pub async fn populate_idev_mldsa87_cert<A: ApiAlloc>(alloc: &A, cert: &[u8]) -> McuResult<()> {
    if cert.is_empty() || cert.len() > POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE {
        return Err(INVARIANT);
    }

    let mut bytesum = 0u32;
    for b in cert {
        bytesum = bytesum.wrapping_add(u32::from(*b));
    }
    let header = populate_idev_mldsa87_header(cert.len() as u32, bytesum);

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let _rsp_len = crate::wire::mbox_execute_slice(
        CMD_POPULATE_IDEV_MLDSA87_CERT,
        Some(header.as_bytes()),
        cert,
        &mut rsp,
    )
    .await?;

    Ok(())
}

/// Build the `chksum(4) | cert_size(4)` request header for
/// `POPULATE_IDEV_MLDSA87_CERT`.
///
/// The mailbox checksum covers the certificate bytes as well as the header.
/// Because [`calc_checksum`] already returns the *negated* running sum, folding
/// in the payload's byte-sum is a single subtraction:
/// `0 - (S_hdr + S_cert) == calc_checksum(cmd, hdr) - S_cert`.
fn populate_idev_mldsa87_header(cert_size: u32, cert_bytesum: u32) -> PopulateIdevCertReqHeader {
    let mut header = PopulateIdevCertReqHeader {
        // chksum stays 0 while it is summed over, matching Caliptra, which
        // verifies over the payload following that field.
        chksum: U32::new(0),
        cert_size: U32::new(cert_size),
    };
    let chksum =
        calc_checksum(CMD_POPULATE_IDEV_MLDSA87_CERT, header.as_bytes()).wrapping_sub(cert_bytesum);
    header.chksum = U32::new(chksum);
    header
}

// ---------------------------------------------------------------------------
// GET_*_CSR — in-place response handling
// ---------------------------------------------------------------------------

/// Bytes preceding variable CSR data in a mailbox response:
/// `MailboxRespHeader(8) | data_size(4)`.
const CSR_RSP_PREFIX_LEN: usize = MBOX_RESP_HEADER_SIZE + 4;

/// Issue `GET_IDEV_ECC384_CSR` and write the returned CSR DER bytes into
/// `csr_out`. Returns `Ok(None)` when the CSR is not provisioned.
#[inline(never)]
pub async fn get_idev_csr_ecc384(csr_out: &mut [u8]) -> McuResult<Option<usize>> {
    if csr_out.len() <= CSR_RSP_PREFIX_LEN {
        return Err(INVARIANT);
    }

    let mut req = [0u8; 4];
    req.copy_from_slice(&calc_checksum(CMD_GET_IDEV_ECC384_CSR, &[]).to_le_bytes());

    let actual = crate::wire::mbox_execute(CMD_GET_IDEV_ECC384_CSR, &req, csr_out).await?;
    if actual < CSR_RSP_PREFIX_LEN {
        return Err(INVARIANT);
    }
    let data_size = u32::from_le_bytes([csr_out[8], csr_out[9], csr_out[10], csr_out[11]]);
    if data_size == u32::MAX {
        return Ok(None);
    }
    let data_size = data_size as usize;
    if data_size == 0
        || data_size > csr_out.len() - CSR_RSP_PREFIX_LEN
        || CSR_RSP_PREFIX_LEN + data_size > actual
    {
        return Err(INVARIANT);
    }
    csr_out.copy_within(CSR_RSP_PREFIX_LEN..CSR_RSP_PREFIX_LEN + data_size, 0);
    Ok(Some(data_size))
}

/// `GET_ATTESTED_*_CSR` request size on the wire:
/// `chksum(4) | key_id(4) | nonce(32)` = 40 B.
const ATTESTED_CSR_REQ_LEN: usize = 40;

/// Issue `GET_ATTESTED_ECC384_CSR` and write the returned CSR DER bytes into
/// `csr_out`, returning the number of bytes written.
///
/// `csr_out` is also used as the mailbox response buffer for the duration of
/// the call; on return, only the CSR data occupies its prefix. The caller must
/// provide a `csr_out` of at least [`CSR_RSP_PREFIX_LEN`] bytes plus
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
    if csr_out.len() <= CSR_RSP_PREFIX_LEN {
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
    if actual < CSR_RSP_PREFIX_LEN {
        return Err(INVARIANT);
    }
    let data_size = u32::from_le_bytes([csr_out[8], csr_out[9], csr_out[10], csr_out[11]]) as usize;
    if data_size == 0
        || data_size > csr_out.len() - CSR_RSP_PREFIX_LEN
        || CSR_RSP_PREFIX_LEN + data_size > actual
    {
        return Err(INVARIANT);
    }
    csr_out.copy_within(CSR_RSP_PREFIX_LEN..CSR_RSP_PREFIX_LEN + data_size, 0);
    Ok(data_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The streamed checksum must equal the long-hand form Caliptra verifies:
    /// `0 - (sum(cmd LE) + sum(cert_size LE) + sum(cert bytes))`. This pins the
    /// `calc_checksum(...) - bytesum` folding, including u32 wraparound.
    #[test]
    fn mldsa87_header_checksum_matches_longhand() {
        for &(cert_size, bytesum) in &[
            (7741u32, 0x0012_3456u32),
            (1, 0),
            (8192, u32::MAX),
            (547, 12_345),
        ] {
            let header = populate_idev_mldsa87_header(cert_size, bytesum);
            assert_eq!(header.cert_size.get(), cert_size);
            // Field order on the wire, not just the values.
            assert_eq!(&header.as_bytes()[4..8], &cert_size.to_le_bytes());

            let mut sum = bytesum;
            for b in CMD_POPULATE_IDEV_MLDSA87_CERT.to_le_bytes().iter() {
                sum = sum.wrapping_add(u32::from(*b));
            }
            for b in cert_size.to_le_bytes().iter() {
                sum = sum.wrapping_add(u32::from(*b));
            }
            let expected = 0u32.wrapping_sub(sum);

            assert_eq!(
                header.chksum.get(),
                expected,
                "cert_size={cert_size} bytesum={bytesum:#010x}"
            );
        }
    }

    /// The length check that guards the wire format, as a pure predicate so it
    /// can be tested on the host. Kept in lockstep with the guard at the top of
    /// [`populate_idev_mldsa87_cert`].
    fn mldsa87_cert_len_ok(cert_len: usize) -> bool {
        cert_len != 0 && cert_len <= POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE
    }

    /// An empty or over-long certificate must be rejected before it reaches the
    /// mailbox: Caliptra caps the request at `MAX_CERT_SIZE` and would reject a
    /// longer one with a data-length error.
    #[test]
    fn mldsa87_length_guards() {
        assert!(!mldsa87_cert_len_ok(0), "empty cert");
        assert!(
            !mldsa87_cert_len_ok(POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE + 1),
            "over Caliptra's MAX_CERT_SIZE"
        );
        // The emulator's ML-DSA-87 IDevID cert, and the exact cap.
        assert!(mldsa87_cert_len_ok(7741));
        assert!(mldsa87_cert_len_ok(POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE));
    }

    /// The ECC-384 cap and partition bound, which decide whether an erased or
    /// short partition reaches Caliptra.
    #[test]
    fn ecc384_cert_der_len_cases() {
        // The emulator fixture: 30 82 02 1f -> 0x021f + 4 = 547.
        let good = u32::from_le_bytes([0x30, 0x82, 0x02, 0x1f]);
        assert_eq!(ecc384_cert_der_len(good, 547), Some(547));
        // Erased OTP - the case that matters.
        assert_eq!(ecc384_cert_der_len(u32::MAX, 547), None);
        assert_eq!(ecc384_cert_der_len(0, 547), None);
        // A cert one byte longer than its partition would splice 0xFF fill.
        assert_eq!(ecc384_cert_der_len(good, 546), None);
        // Past Caliptra's 1024-byte ECC cap even though the partition allows it.
        let over_cap = u32::from_le_bytes([0x30, 0x82, 0x04, 0x00]); // 1024 + 4
        assert_eq!(ecc384_cert_der_len(over_cap, 2048), None);
        // Exactly the cap is accepted.
        let at_cap = u32::from_le_bytes([0x30, 0x82, 0x03, 0xfc]); // 1020 + 4
        assert_eq!(
            ecc384_cert_der_len(at_cap, 2048),
            Some(POPULATE_IDEV_ECC384_MAX_CERT_SIZE)
        );
    }

    /// Every accept/reject path of the DER length discovery. The reject cases
    /// are what keep an unprovisioned or malformed partition from splicing
    /// `0xFF` fill into the ML-DSA attestation chain.
    #[test]
    fn mldsa87_cert_der_len_cases() {
        // `30 82 1e 39` -> body 0x1e39 (7737) + 4 = 7741, the emulator fixture.
        let good = u32::from_le_bytes([0x30, 0x82, 0x1e, 0x39]);
        assert_eq!(mldsa87_cert_der_len(good, 7741), Some(7741));
        assert_eq!(mldsa87_cert_der_len(good, 8192), Some(7741));

        // Erased OTP.
        assert_eq!(mldsa87_cert_der_len(u32::MAX, 7741), None);
        // Wrong tag (0x31 = SET, not SEQUENCE).
        assert_eq!(
            mldsa87_cert_der_len(u32::from_le_bytes([0x31, 0x82, 0x1e, 0x39]), 7741),
            None
        );
        // Short-form length: not a form these certs can take.
        assert_eq!(
            mldsa87_cert_der_len(u32::from_le_bytes([0x30, 0x81, 0x7f, 0x00]), 7741),
            None
        );
        // Zero body.
        assert_eq!(
            mldsa87_cert_der_len(u32::from_le_bytes([0x30, 0x82, 0x00, 0x00]), 7741),
            None
        );
        // One byte past the partition — the 0xFF-fill splice this guards.
        assert_eq!(mldsa87_cert_der_len(good, 7740), None);
        // Past Caliptra's cap even when the partition would allow it.
        let huge = u32::from_le_bytes([0x30, 0x82, 0xff, 0xff]); // 65535 + 4
        assert_eq!(mldsa87_cert_der_len(huge, 65536), None);
    }
}
