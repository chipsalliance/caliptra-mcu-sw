// Licensed under the Apache-2.0 license

//! Certificate-store initialization.
//!
//! Reads the IDevID certificates from OTP, installs them into Caliptra, and
//! configures the cert slots:
//!   - Slot 0 (Vendor): ReadOnly endorsement from static Root CA
//!   - Slot 1 (Owner):  Managed endorsement (flash-backed, initially empty)
//!   - Slot 2 (Tenant): Managed endorsement (flash-backed, initially empty)
//!
//! Each managed slot is backed by two disjoint flash regions, one per
//! asymmetric algorithm, so an ECC and an ML-DSA chain can coexist in
//! the same SPDM slot and be served according to what was negotiated.
//!
//! Caliptra generates the IDevID *keypair* and a self-signed CSR, but never the
//! IDevID *certificate* — that is issued externally and provisioned into OTP.
//! Both the ECC-384 (partition 1) and ML-DSA-87 (partition 2) IDevID certs are
//! read here and prepended to their respective Caliptra cert chains via the
//! `POPULATE_IDEV_*_CERT` mailbox commands.

mod slot0_endorsements;

#[cfg(not(feature = "cert-provisioning"))]
use caliptra_mcu_cert_store::NoEndorsementStorage;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_cert_store::TaskCertStore;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_cert_store::{errors as cert_errors, CertificateAlgorithm, EndorsementStorage};
use caliptra_mcu_cert_store::{CertificateProvisioningPolicy, EndorsementRole, SharedCertStore};
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_scratch_alloc::BitmapAllocator;
// `log_warn!` writes through the console writer, so the trait must be in scope;
// the macro compiles to nothing without a log transport, which makes the import
// look unused.
#[allow(unused_imports)]
use core::fmt::Write as _;
use mcu_caliptra_api::{
    mldsa87_cert_der_len, populate_idev_ecc384_cert, populate_idev_mldsa87_cert, ScratchAlloc,
    POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE,
};
use mcu_error::McuResult;

/// IDevID ECC cert size in OTP partition 1.
const ECC_DEVID_CERT_SIZE: usize = 547;

/// OTP partition ID for the IDevID ECC certificate.
const OTP_IDEVID_ECC_PARTITION: u32 = 0x01;

/// OTP partition ID for the IDevID ML-DSA-87 certificate.
const OTP_IDEVID_MLDSA_PARTITION: u32 = 0x02;

/// Headroom for the mailbox response and bitmap allocator bookkeeping.
const BOOT_SCRATCH_HEADROOM: usize = 1024;

/// Scratch that [`init`] needs for the ML-DSA certificate import. Boot
/// borrows it from an idle task pool.
pub(crate) const BOOT_SCRATCH_SIZE: usize =
    POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE + BOOT_SCRATCH_HEADROOM;

/// SPI flash implementation of [`EndorsementStorage`] for managed endorsements.
#[cfg(feature = "cert-provisioning")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpiFlashEndorsementStorage {
    driver_num: u32,
}

#[cfg(feature = "cert-provisioning")]
impl SpiFlashEndorsementStorage {
    pub(crate) const fn new(driver_num: u32) -> Self {
        Self { driver_num }
    }
}

#[cfg(feature = "cert-provisioning")]
impl EndorsementStorage for SpiFlashEndorsementStorage {
    fn is_available(&self) -> McuResult<bool> {
        match SpiFlash::<DefaultSyscalls>::new(self.driver_num).exists() {
            Ok(()) => Ok(true),
            Err(ErrorCode::NoDevice | ErrorCode::NoSupport | ErrorCode::Uninstalled) => Ok(false),
            Err(err) => Err(map_flash_error(err)),
        }
    }

    async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<()> {
        SpiFlash::<DefaultSyscalls>::new(self.driver_num)
            .read(offset, buf.len(), buf)
            .await
            .map_err(map_flash_error)
    }

    async fn write(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        SpiFlash::<DefaultSyscalls>::new(self.driver_num)
            .write(offset, data.len(), data)
            .await
            .map_err(map_flash_error)
    }

    async fn erase(&self, offset: usize, len: usize) -> McuResult<()> {
        SpiFlash::<DefaultSyscalls>::new(self.driver_num)
            .erase(offset, len)
            .await
            .map_err(map_flash_error)
    }
}

#[cfg(feature = "cert-provisioning")]
fn map_flash_error(err: ErrorCode) -> mcu_error::McuErrorCode {
    match err {
        ErrorCode::Busy => cert_errors::STORAGE_BUSY,
        _ => cert_errors::STORAGE_ERROR,
    }
}

#[cfg(feature = "cert-provisioning")]
pub(crate) type CertStoreStorage = SpiFlashEndorsementStorage;
#[cfg(not(feature = "cert-provisioning"))]
pub(crate) type CertStoreStorage = NoEndorsementStorage;

const PROVISIONING_POLICY: CertificateProvisioningPolicy = CertificateProvisioningPolicy::DEFAULT;

static CERT_STORE: SharedCertStore<CertStoreStorage> =
    SharedCertStore::with_policy(PROVISIONING_POLICY);

#[cfg(feature = "mcu-mbox-service")]
struct MciTaskCertStore(TaskCertStore<CertStoreStorage>);

// SAFETY: `user-app` runs on a single-threaded Embassy executor and
// `MCI_CERT_STORE` is accessed exclusively from the single `mcu_mbox_task`
// via the MCI-only `MC_GET_CERT_CHAIN_INFO`, `MC_GET_CERT_CHAIN`, and
// `MC_SET_CERT_CHAIN` commands.
#[cfg(feature = "mcu-mbox-service")]
unsafe impl Sync for MciTaskCertStore {}

#[cfg(feature = "mcu-mbox-service")]
static MCI_CERT_STORE: MciTaskCertStore = MciTaskCertStore(TaskCertStore::new(&CERT_STORE));

/// Each managed `(role, algorithm)` gets its own flash region so that
/// installing one algorithm's chain cannot erase the other's.
#[cfg(feature = "cert-provisioning")]
const MANAGED_ENDORSEMENT_REGIONS: &[(EndorsementRole, CertificateAlgorithm)] = &[
    (EndorsementRole::Owner, CertificateAlgorithm::EccP384),
    (EndorsementRole::Owner, CertificateAlgorithm::MlDsa87),
    (EndorsementRole::Tenant, CertificateAlgorithm::EccP384),
    (EndorsementRole::Tenant, CertificateAlgorithm::MlDsa87),
];
/// Region size. The partition is statically sized, so subdividing it
/// four ways instead of two costs no additional flash. ML-DSA chains
/// are roughly an order of magnitude larger than ECC ones, so the
/// remaining room per region still far exceeds what either needs.
#[cfg(feature = "cert-provisioning")]
const MANAGED_SLOT_REGION_SIZE: usize = {
    assert!(!MANAGED_ENDORSEMENT_REGIONS.is_empty());
    assert!(CERT_STORE_PARTITION.size % MANAGED_ENDORSEMENT_REGIONS.len() == 0);
    CERT_STORE_PARTITION.size / MANAGED_ENDORSEMENT_REGIONS.len()
};

/// Initialize Caliptra identity chains before any SPDM or MCU-mailbox task can
/// contend for the mailbox, then configure endorsement chains in the shared
/// certificate store.
///
/// `scratch` must provide at least [`BOOT_SCRATCH_SIZE`] bytes.
pub(crate) async fn init(scratch: &BitmapAllocator) -> McuResult<()> {
    populate_idev(scratch).await?;
    setup_endorsements(&CERT_STORE, scratch).await?;
    Ok(())
}

pub(crate) fn shared() -> &'static SharedCertStore<CertStoreStorage> {
    &CERT_STORE
}

#[cfg(feature = "mcu-mbox-service")]
pub(crate) fn mci_store() -> &'static TaskCertStore<CertStoreStorage> {
    &MCI_CERT_STORE.0
}

/// One-time Caliptra setup: read the IDevID certs from OTP and install them.
///
/// Boot initialization invokes this before spawning any mailbox-using task, so
/// the installs cannot contend with an SPDM responder or the MCU mailbox
/// service. ECC-384 is required; ML-DSA-87 remains best-effort until SPDM can
/// negotiate that algorithm.
async fn populate_idev<A: ScratchAlloc>(alloc: &A) -> McuResult<()> {
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
async fn setup_endorsements<A: ScratchAlloc>(
    store: &SharedCertStore<CertStoreStorage>,
    alloc: &A,
) -> McuResult<()> {
    // Vendor: ReadOnly endorsement with static Root CA (ECC & ML-DSA).
    store
        .init_readonly_endorsement(
            alloc,
            EndorsementRole::Vendor,
            slot0_endorsements::SLOT0_ECC_ROOT_CERT_CHAIN,
            Some(slot0_endorsements::SLOT0_MLDSA_ROOT_CERT_CHAIN),
        )
        .await?;

    // Owner/Tenant: Managed endorsements, initially empty or loaded from the
    // cert-store flash partition. Each (role, algorithm) gets its own
    // contiguous region. This remains test-only until a production requester
    // authorization exists.
    #[cfg(feature = "cert-provisioning")]
    {
        let storage = SpiFlashEndorsementStorage::new(CERT_STORE_PARTITION.driver_num);
        for (region_index, &(role, algo)) in MANAGED_ENDORSEMENT_REGIONS.iter().enumerate() {
            store
                .init_managed_endorsement(
                    role,
                    algo,
                    storage,
                    region_index * MANAGED_SLOT_REGION_SIZE,
                    MANAGED_SLOT_REGION_SIZE,
                )
                .await?;
        }
    }

    Ok(())
}

/// Read the IDevID ECC-384 cert from OTP and install it into Caliptra.
async fn populate_idev_cert_from_otp_ecc<A: ScratchAlloc>(alloc: &A) -> McuResult<()> {
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
async fn populate_idev_cert_from_otp_mldsa<A: ScratchAlloc>(alloc: &A) -> McuResult<()> {
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
    // Length policy lives in mcu-caliptra-api so it is covered by host unit tests;
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
