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
// the macro compiles to nothing without a log transport, which makes the import
// look unused.
#[allow(unused_imports)]
use core::fmt::Write as _;
use mcu_caliptra_api::{
    is_der_cert_header, mldsa87_cert_der_len, populate_idev_ecc384_cert,
    populate_idev_mldsa87_cert, ApiAlloc,
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

/// Mailbox-busy retries allowed for the *best-effort* ML-DSA-87 install.
///
/// Generous, because the contending operation can be a full ECDSA-P384 signature
/// over a large SPDM transcript, but finite: nothing reads the ML-DSA chain yet,
/// so giving up and logging is strictly better than a task that lingers forever
/// re-arming against a mailbox somebody else owns.
const MLDSA_INSTALL_MAX_ATTEMPTS: u32 = 64;

/// Retry `$op` while Caliptra's mailbox is held by another task, **yielding**
/// between attempts. With a second argument, also give up after that many
/// attempts and return `MAILBOX_BUSY`.
///
/// The yield is the load-bearing part. These operations run concurrently with
/// the SPDM responders (which hold the same mailbox for every
/// CHALLENGE/MEASUREMENTS signature) and with the PLDM and MCU-mailbox services.
/// A bare `continue` re-polls this task without ever handing the single-threaded
/// cooperative executor back, so the task that would *release* the mailbox never
/// runs: the retry can never succeed, the app spins at 100% CPU, and every later
/// SPDM request times out.
///
/// Whether to bound it is a separate, per-call-site question, and the answer is
/// not the same everywhere:
///
/// * On the **critical path** (slot-0 endorsement, ECC-384 install) a bound would
///   trade a wait for a hard failure, and failing cert-store init means no SPDM
///   at all. A legitimate holder can be slow — a PLDM firmware-update
///   verification holds the mailbox far longer than a signature — so waiting is
///   the correct outcome and the yield alone removes the live-lock.
/// * On the **best-effort ML-DSA path** nothing consumes the result, so a bound
///   is free and keeps a stuck mailbox from leaving a task alive forever.
macro_rules! retry_on_mailbox_busy {
    ($op:expr) => {{
        // `$op` is re-evaluated per attempt: a future cannot be polled again
        // after it completes.
        loop {
            match $op.await {
                Ok(v) => break Ok(v),
                Err(e) if e == mcu_error::codes::MAILBOX_BUSY => {
                    // Hand the executor back so the mailbox owner can finish.
                    yield_now().await;
                }
                Err(e) => break Err(e),
            }
        }
    }};
    ($op:expr, $max_attempts:expr) => {{
        let mut attempts = 0u32;
        loop {
            match $op.await {
                Ok(v) => break Ok(v),
                Err(e) if e == mcu_error::codes::MAILBOX_BUSY => {
                    attempts += 1;
                    if attempts > $max_attempts {
                        break Err(e);
                    }
                    yield_now().await;
                }
                Err(e) => break Err(e),
            }
        }
    }};
}

/// Yield to the executor once, so another task can make progress.
///
/// Hand-rolled rather than adding `embassy-futures` for one function: wake
/// immediately and return `Pending` exactly once, which re-queues this task
/// behind the others instead of busy-spinning.
async fn yield_now() {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    struct YieldNow(bool);
    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    YieldNow(false).await
}

/// One-time Caliptra setup: read the IDevID certs from OTP and install them.
///
/// Only the ECC-384 install runs here; its failure fails cert-store init, which
/// leaves slot 0 unprovisioned but no longer stops the responders from serving.
/// The ML-DSA-87 install is best-effort and lives in its own task.
pub async fn populate_idev<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    populate_idev_from_otp(alloc).await
}

/// Install the IDevID ML-DSA-87 cert, off the responder-startup path.
///
/// Separate from [`populate_idev`] because the OTP driver reads 4 bytes per
/// syscall: 1,936 reads for this cert against the ECC cert's 137, which delayed
/// responder startup past the point a connected requester gives up.
///
/// Best-effort — errors are logged, not returned, so a PQC-provisioning defect
/// cannot disturb the live ECC chain. Every exit leaves a distinct warning, and
/// the mailbox-busy retry is bounded and yields.
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
    retry_on_mailbox_busy!(store.set_endorsement_chain(
        alloc,
        VENDOR_STORE_SLOT,
        slot0_endorsements::SLOT0_ECC_ROOT_CERT_CHAIN,
        0, // key_pair_id
    ))?;

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
///
/// Skips the install when partition 1 is unprovisioned. Nothing downstream
/// parses the DER, so submitting an erased partition would splice 547 bytes of
/// `0xFF` into the attestation chain and still report success.
async fn populate_idev_from_otp<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    let mut cert_buf = [0u8; ECC_DEVID_CERT_SIZE];
    let otp = ExternalOtp::<DefaultSyscalls>::new();

    if !otp_holds_der_cert(&otp, OTP_IDEVID_ECC_PARTITION).await? {
        let mut cw = Console::<DefaultSyscalls>::writer();
        crate::log_warn!(cw, "SPDM: no ECC-384 IDevID cert in OTP; skipping install");
        return Ok(());
    }

    // Same word-at-a-time read as the ML-DSA path; 547 is not a word multiple,
    // so the final word contributes 3 bytes.
    read_otp_range(&otp, OTP_IDEVID_ECC_PARTITION, &mut cert_buf).await?;

    retry_on_mailbox_busy!(populate_idev_ecc384_cert(alloc, &cert_buf))
}

/// Whether an OTP partition holds a DER certificate rather than erased fill.
///
/// Header policy lives in api-lite so it is covered by host unit tests;
/// user-app itself is excluded from `cargo test` (xtask/src/test.rs).
async fn otp_holds_der_cert(
    otp: &ExternalOtp<DefaultSyscalls>,
    partition_id: u32,
) -> McuResult<bool> {
    let word = otp
        .read(partition_id, 0)
        .await
        .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
    Ok(is_der_cert_header(word))
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
        // so: this is the branch that decides a device ships without a PQC
        // IDevID, so the log has to distinguish it from a successful install.
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

    retry_on_mailbox_busy!(
        populate_idev_mldsa87_cert(alloc, &cert),
        MLDSA_INSTALL_MAX_ATTEMPTS
    )
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
/// The driver returns one 32-bit word per call from a byte offset, clamping a
/// read that would straddle the partition end and padding with `0xFF`
/// (`platforms/emulator/runtime/kernel/drivers/external_otp/src/ext_flash_otp.rs`
/// `read`). `out.len()` need not be a word multiple — the ML-DSA-87 cert is
/// 7741 bytes — so the last word contributes only `total - offset` bytes.
///
/// Panic-free by construction, which matters because a panic in this app is
/// fatal: there is no slice indexing here at all. `zip` stops at the shorter of
/// the two iterators, so the destination's remaining length truncates the source
/// word for free and no index can be out of range.
async fn read_otp_range(
    otp: &ExternalOtp<DefaultSyscalls>,
    partition_id: u32,
    out: &mut [u8],
) -> McuResult<()> {
    let total = out.len();
    let mut offset = 0usize;

    while offset < total {
        let word = otp
            .read(partition_id, offset as u32)
            .await
            .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
        // Bytes this word contributes: 4, or fewer on the trailing partial word.
        let n = (total - offset).min(4);
        for (d, s) in out.iter_mut().skip(offset).zip(word.to_le_bytes().iter()) {
            *d = *s;
        }
        offset += n;
    }

    Ok(())
}
