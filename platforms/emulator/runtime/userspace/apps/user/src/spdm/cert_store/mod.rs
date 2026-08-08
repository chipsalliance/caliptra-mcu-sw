// Licensed under the Apache-2.0 license

//! Cert store initialization for the spdm-lib emulator platform.
//!
//! Reads the IDevID certificates from OTP, installs them into Caliptra, and
//! configures the cert slots:
//!   - Slot 0 (Vendor): ReadOnly endorsement from static Root CA
//!   - Slot 1 (Owner):  Managed endorsement (flash-backed, initially empty)
//!   - Slot 2 (Tenant): Managed endorsement (flash-backed, initially empty)
//!
//! Caliptra generates the IDevID *keypair* and a self-signed CSR, but never the
//! IDevID *certificate* — that is issued externally and provisioned into OTP.
//! Both the ECC-384 (partition 1) and ML-DSA-87 (partition 2) IDevID certs are
//! read here and prepended to their respective Caliptra cert chains via the
//! `POPULATE_IDEV_*_CERT` mailbox commands.

mod slot0_endorsements;

#[cfg(feature = "test-mctp-spdm-set-certificate")]
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_spdm_pal::cert::store::SharedCertStore;
// `log_warn!` writes through the console writer, so the trait must be in scope;
// but the macro compiles to nothing in configurations without a log transport,
// which makes the import look unused. Same treatment as spdm/mod.rs.
#[allow(unused_imports)]
use core::fmt::Write as _;
use mcu_caliptra_api_lite::{
    mldsa87_cert_der_len, populate_idev_ecc384_cert, populate_idev_mldsa87_cert, ApiAlloc,
};
use mcu_error::McuResult;

/// SPDM slot IDs for OCP PKI entities.
const VENDOR_STORE_SLOT: usize = 0;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const OWNER_SPDM_SLOT: u8 = 2;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const TENANT_SPDM_SLOT: u8 = 3;

/// IDevID ECC cert size in OTP partition 1.
const ECC_DEVID_CERT_SIZE: usize = 547;

/// OTP partition ID for the IDevID ECC certificate.
const OTP_IDEVID_ECC_PARTITION: u32 = 0x01;

/// OTP partition ID for the IDevID ML-DSA-87 certificate.
const OTP_IDEVID_MLDSA_PARTITION: u32 = 0x02;

#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_COUNT: usize = 2;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_REGION_SIZE: usize = CERT_STORE_PARTITION.size / MANAGED_SLOT_COUNT;

/// One-time Caliptra setup: read the IDevID certs from OTP and install them.
///
/// The ECC-384 install is required — its failure aborts cert-store init because
/// every SPDM flow in use today signs with ECC. The ML-DSA-87 install is
/// best-effort and *cannot* fail this function: no SPDM requester can negotiate
/// ML-DSA today (`AsymAlgos` has no PQC codepoint), so a PQC-provisioning defect
/// must not take down the ECC chain that attestation actually depends on.
pub async fn populate_idev<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    populate_idev_from_otp(alloc).await
}

/// Install the IDevID ML-DSA-87 cert, off the responder-startup path.
///
/// Deliberately *not* part of [`populate_idev`]. The OTP driver reads 4 bytes
/// per syscall, so a 7741-byte certificate costs 1,936 sequential reads against
/// the ECC certificate's 137. Doing that before the responders start delays
/// them past the point where a requester that is already connected gives up
/// ("Error sending SPDM request"). Nothing can read the ML-DSA chain yet, so the
/// install has no reason to gate SPDM coming up.
///
/// Failures are logged and swallowed: no SPDM requester can negotiate ML-DSA
/// today (`AsymAlgos` has no PQC codepoint), so a PQC-provisioning defect must
/// not disturb the ECC chain that attestation actually depends on. An
/// unprovisioned or unreadable PQC IDevID on a device that should have one is a
/// provisioning escape, so it is reported rather than dropped silently.
pub async fn populate_idev_mldsa<A: ApiAlloc>(alloc: &A) {
    if let Err(e) = populate_idev_mldsa_from_otp(alloc).await {
        let mut cw = Console::<DefaultSyscalls>::writer();
        crate::log_warn!(
            cw,
            "SPDM: ML-DSA-87 IDevID cert not installed: 0x{}",
            crate::Hex32(u32::from(e))
        );
    }
}

/// Configure endorsement chains on the shared cert store, for all 3 slots.
///
/// Called once from spdm_task before spawning responders. Slot 0 failure is
/// fatal. Slots 1-2 stay unprovisioned if flash is empty (they'll be
/// provisioned via SET_CERTIFICATE).
pub async fn setup_endorsements<A: ApiAlloc>(store: &SharedCertStore, alloc: &A) -> McuResult<()> {
    // Slot 0 (Vendor): ReadOnly endorsement with static Root CA.
    // Retry on mailbox busy (SHA calls during root cert hashing).
    loop {
        match store
            .set_endorsement_chain(
                alloc,
                VENDOR_STORE_SLOT,
                slot0_endorsements::SLOT0_ECC_ROOT_CERT_CHAIN,
                0, // key_pair_id
            )
            .await
        {
            Ok(()) => break,
            Err(e) if e == mcu_error::codes::MAILBOX_BUSY => continue,
            Err(e) => return Err(e),
        }
    }

    // Slots 1-2 (Owner/Tenant): Managed endorsement, initially empty or loaded
    // from the cert-store flash partition. This remains test-only until a
    // production authorization/key-binding policy exists.
    #[cfg(feature = "test-mctp-spdm-set-certificate")]
    {
        store
            .set_managed_endorsement(
                1,
                OWNER_SPDM_SLOT,
                CERT_STORE_PARTITION.driver_num,
                0,
                MANAGED_SLOT_REGION_SIZE,
            )
            .await?;
        store
            .set_managed_endorsement(
                2,
                TENANT_SPDM_SLOT,
                CERT_STORE_PARTITION.driver_num,
                MANAGED_SLOT_REGION_SIZE,
                MANAGED_SLOT_REGION_SIZE,
            )
            .await?;
    }

    Ok(())
}

/// Read the IDevID ECC-384 cert from OTP and install it into Caliptra.
async fn populate_idev_from_otp<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    let mut cert_buf = [0u8; ECC_DEVID_CERT_SIZE];
    let otp = ExternalOtp::<DefaultSyscalls>::new();

    let mut offset = 0u32;
    while offset + 4 <= ECC_DEVID_CERT_SIZE as u32 {
        let word = otp
            .read(OTP_IDEVID_ECC_PARTITION, offset)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
        // Panic-free word store: fixed-size array write lowers to a memcpy with
        // no bounds/length panic (loop guard guarantees 4 bytes of room).
        let slot = cert_buf
            .get_mut(offset as usize..)
            .and_then(|s| s.first_chunk_mut::<4>())
            .ok_or(mcu_error::codes::INVARIANT)?;
        *slot = word.to_le_bytes();
        offset += 4;
    }
    // Handle remaining 3 bytes (547 % 4 == 3).
    if (offset as usize) < ECC_DEVID_CERT_SIZE {
        let tail_offset = ECC_DEVID_CERT_SIZE as u32 - 4;
        let word = otp
            .read(OTP_IDEVID_ECC_PARTITION, tail_offset)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
        let word_bytes = word.to_le_bytes();
        let skip = (offset - tail_offset) as usize;
        // Panic-free tail store: copy word_bytes[skip..] without indexing.
        for (d, s) in cert_buf
            .iter_mut()
            .skip(tail_offset as usize + skip)
            .zip(word_bytes.iter().skip(skip))
        {
            *d = *s;
        }
    }

    // Install into Caliptra. Retry on mailbox busy.
    loop {
        match populate_idev_ecc384_cert(alloc, &cert_buf).await {
            Ok(()) => break,
            Err(e) if e == mcu_error::codes::MAILBOX_BUSY => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Read the IDevID ML-DSA-87 cert from OTP and install it into Caliptra.
///
/// Best-effort: if the partition holds no usable DER certificate the install is
/// skipped and `Ok(())` is returned so the ECC chain still comes up.
///
/// The certificate is staged in scratch and sent as one contiguous payload
/// rather than streamed out of OTP. `execute_with_payload_stream` takes the
/// mailbox mutex *before* pulling from the stream, so streaming would hold the
/// Caliptra mailbox with EXECUTE asserted across ~1,900 sequential 4-byte OTP
/// syscalls — long enough to starve an SPDM requester that is already
/// connected. Staging keeps the mailbox held only for the transfer itself.
async fn populate_idev_mldsa_from_otp<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    let otp = ExternalOtp::<DefaultSyscalls>::new();

    // Submit the cert's own DER length, not the whole partition: a production
    // cert shorter than its partition would otherwise splice the 0xFF fill into
    // the chain.
    let Some(cert_size) = mldsa_cert_der_len(&otp).await? else {
        // No cert provisioned — leave the MLDSA chain as Caliptra built it. Say
        // so: this is the branch that silently decides a device ships without a
        // PQC IDevID, so it must not be indistinguishable from a successful
        // install in the log.
        let mut cw = Console::<DefaultSyscalls>::writer();
        crate::log_warn!(
            cw,
            "SPDM: no ML-DSA-87 IDevID cert in OTP; skipping install"
        );
        return Ok(());
    };

    // Stage the cert outside the mailbox lock. The scratch pool is untouched at
    // cert-store init, so the ~7.7 KiB fits without a stack buffer.
    let mut cert = alloc.alloc(cert_size)?;
    read_otp_range(&otp, OTP_IDEVID_MLDSA_PARTITION, &mut cert).await?;

    // Install into Caliptra. Retry on mailbox busy.
    loop {
        match populate_idev_mldsa87_cert(alloc, &cert).await {
            Ok(()) => break,
            Err(e) if e == mcu_error::codes::MAILBOX_BUSY => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Determine the ML-DSA-87 IDevID cert length from its own DER header.
///
/// A certificate is an ASN.1 SEQUENCE: tag `0x30`, then a long-form length.
/// `0x82` (2 length bytes) is the only form these certs can take: the ML-DSA-87
/// signature alone exceeds 4 KiB, so the body is always in `128..=65535`.
///
/// Returns `Ok(None)` for anything that is not a cert this device can install —
/// erased OTP, a truncated header, or a length that overruns the partition.
/// All of those mean "no usable PQC cert provisioned", which the caller skips;
/// none of them should be able to take down the ECC chain.
async fn mldsa_cert_der_len(otp: &ExternalOtp<DefaultSyscalls>) -> McuResult<Option<usize>> {
    let word = otp
        .read(OTP_IDEVID_MLDSA_PARTITION, 0)
        .await
        .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
    let partition_size = otp
        .partition_size(OTP_IDEVID_MLDSA_PARTITION)
        .map_err(|_| mcu_error::codes::INTERNAL_BUG)? as usize;
    // Length policy lives in api-lite so it is covered by host unit tests;
    // user-app itself is excluded from `cargo test` (xtask/src/test.rs).
    Ok(mldsa87_cert_der_len(word, partition_size))
}

/// Read `out.len()` bytes from the start of an OTP partition.
///
/// The driver is word-addressed, so whole 32-bit words are copied and any
/// trailing 1..3 bytes are taken from the final word (the ML-DSA-87 cert is
/// 7741 bytes, i.e. not a word multiple). Panic-free: every store goes through
/// a checked slice, since a panic in this app is fatal.
async fn read_otp_range(
    otp: &ExternalOtp<DefaultSyscalls>,
    partition_id: u32,
    out: &mut [u8],
) -> McuResult<()> {
    let total = out.len();
    let mut offset = 0usize;

    while offset + 4 <= total {
        let word = otp
            .read(partition_id, offset as u32)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
        let slot = out
            .get_mut(offset..)
            .and_then(|s| s.first_chunk_mut::<4>())
            .ok_or(mcu_error::codes::INVARIANT)?;
        *slot = word.to_le_bytes();
        offset += 4;
    }

    // Trailing bytes: read the word containing them and copy only what is left.
    if offset < total {
        let word = otp
            .read(partition_id, offset as u32)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
        let word_bytes = word.to_le_bytes();
        for (d, s) in out.iter_mut().skip(offset).zip(word_bytes.iter()) {
            *d = *s;
        }
    }

    Ok(())
}
