// Licensed under the Apache-2.0 license

//! Certificate-store initialization.
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

extern crate alloc;

#[cfg(feature = "spdm")]
mod slot0_endorsements;

#[cfg(feature = "test-mctp-spdm-set-certificate")]
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_scratch_alloc::{BitmapAllocator, BITMAP_SLOT_SIZE};
#[cfg(feature = "spdm")]
use caliptra_mcu_spdm_pal::cert::store::SharedCertStore;
// `log_warn!` writes through the console writer, so the trait must be in scope;
// the macro compiles to nothing without a log transport, which makes the import
// look unused.
#[allow(unused_imports)]
use core::fmt::Write as _;
use core::ptr::NonNull;
use mcu_caliptra_api::{
    mldsa87_cert_der_len, populate_idev_ecc384_cert, populate_idev_mldsa87_cert, ApiAlloc,
};
use mcu_error::McuResult;

/// SPDM slot IDs for OCP PKI entities.
#[cfg(feature = "spdm")]
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

/// Temporary boot pool for the ML-DSA certificate plus mailbox response.
///
/// This reuses the global heap after measurement boot releases its temporary
/// allocation, and is released before any service task is spawned.
const CERT_STORE_BOOT_SCRATCH_SIZE: usize = 9 * 1024;
const CERT_STORE_BOOT_SCRATCH_SLOTS: usize = CERT_STORE_BOOT_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct CertStoreBootScratchSlot([u8; BITMAP_SLOT_SIZE]);

#[cfg(feature = "spdm")]
static CERT_STORE: SharedCertStore = SharedCertStore::new();

#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_COUNT: usize = 2;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_REGION_SIZE: usize = CERT_STORE_PARTITION.size / MANAGED_SLOT_COUNT;

/// Initialize Caliptra identity chains before any SPDM or MCU-mailbox task can
/// contend for the mailbox, then configure SPDM endorsements when enabled.
pub(crate) async fn boot_init() -> McuResult<()> {
    let mut scratch = alloc::vec::Vec::new();
    scratch
        .try_reserve_exact(CERT_STORE_BOOT_SCRATCH_SLOTS)
        .map_err(|_| mcu_error::codes::OUT_OF_MEMORY)?;
    scratch.resize(
        CERT_STORE_BOOT_SCRATCH_SLOTS,
        CertStoreBootScratchSlot([0; BITMAP_SLOT_SIZE]),
    );
    let scratch_ptr =
        NonNull::new(scratch.as_mut_ptr().cast::<u8>()).ok_or(mcu_error::codes::OUT_OF_MEMORY)?;

    // SAFETY: `scratch_ptr` points at aligned heap memory owned by `scratch`.
    // The vector outlives every allocation, and no allocation escapes.
    let allocator = unsafe { BitmapAllocator::new(scratch_ptr, CERT_STORE_BOOT_SCRATCH_SIZE) };

    populate_idev(&allocator).await?;
    #[cfg(feature = "spdm")]
    setup_endorsements(&CERT_STORE, &allocator).await?;
    Ok(())
}

#[cfg(feature = "spdm")]
pub(crate) fn shared() -> &'static SharedCertStore {
    &CERT_STORE
}

/// One-time Caliptra setup: read the IDevID certs from OTP and install them.
///
/// Boot initialization invokes this before spawning any mailbox-using task, so
/// the installs cannot contend with an SPDM responder or the MCU mailbox
/// service. ECC-384 is required; ML-DSA-87 remains best-effort until SPDM can
/// negotiate that algorithm.
async fn populate_idev<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    populate_idev_cert_from_otp_ecc(alloc).await?;
    if let Err(e) = populate_idev_cert_from_otp_mldsa(alloc).await {
        let mut cw = Console::<DefaultSyscalls>::writer();
        crate::log_warn!(
            cw,
            "CERT_STORE: ML-DSA-87 IDevID cert not installed: 0x{}",
            crate::Hex32(u32::from(e))
        );
    }
    Ok(())
}

/// Configure endorsement chains on the shared cert store, for all 3 slots.
///
/// Called once during boot initialization before spawning responders. Slot 0
/// failure is fatal. Slots 1-2 stay unprovisioned if flash is empty (they'll be
/// provisioned via SET_CERTIFICATE).
#[cfg(feature = "spdm")]
async fn setup_endorsements<A: ApiAlloc>(store: &SharedCertStore, alloc: &A) -> McuResult<()> {
    // Slot 0 (Vendor): ReadOnly endorsement with static Root CA.
    store
        .set_endorsement_chain(
            alloc,
            VENDOR_STORE_SLOT,
            slot0_endorsements::SLOT0_ECC_ROOT_CERT_CHAIN,
            0, // key_pair_id
        )
        .await?;

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
async fn populate_idev_cert_from_otp_ecc<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    let mut cert_buf = [0u8; ECC_DEVID_CERT_SIZE];
    let otp = ExternalOtp::<DefaultSyscalls>::new();

    // Same word-at-a-time read as the ML-DSA path; 547 is not a word multiple,
    // so the final word contributes 3 bytes.
    read_otp_range(&otp, OTP_IDEVID_ECC_PARTITION, &mut cert_buf).await?;

    populate_idev_ecc384_cert(alloc, &cert_buf).await
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
/// syscalls. Staging keeps the mailbox held only for the transfer itself.
async fn populate_idev_cert_from_otp_mldsa<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    let otp = ExternalOtp::<DefaultSyscalls>::new();

    // Submit the cert's own DER length, not the whole partition: a production
    // cert shorter than its partition would otherwise splice the 0xFF fill into
    // the chain.
    let Some(cert_size) = mldsa_cert_der_len(&otp).await? else {
        // An empty ML-DSA partition is a supported configuration.
        return Ok(());
    };

    // Stage the cert outside the mailbox lock. The scratch pool is untouched at
    // cert-store init, so the ~7.7 KiB fits without a stack buffer.
    let mut cert = alloc.alloc(cert_size)?;
    read_otp_range(&otp, OTP_IDEVID_MLDSA_PARTITION, &mut cert).await?;

    populate_idev_mldsa87_cert(alloc, &cert).await
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
/// `read`). `out.len()` need not be a word multiple, so the last word
/// contributes only `total - offset` bytes.
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
