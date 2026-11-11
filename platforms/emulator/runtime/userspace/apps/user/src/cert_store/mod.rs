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

#[cfg(not(feature = "vendor-certs-oob"))]
mod slot0_endorsements;

#[cfg(any(not(feature = "vendor-certs-oob"), feature = "cert-provisioning"))]
use caliptra_mcu_cert_store::CertificateAlgorithm;
#[cfg(not(feature = "cert-provisioning"))]
use caliptra_mcu_cert_store::NoEndorsementStorage;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_cert_store::TaskCertStore;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_cert_store::{errors as cert_errors, EndorsementStorage};
use caliptra_mcu_cert_store::{CertificateProvisioningPolicy, EndorsementRole, SharedCertStore};
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
#[cfg(not(feature = "vendor-certs-oob"))]
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
#[cfg(any(not(feature = "vendor-certs-oob"), feature = "cert-provisioning"))]
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
#[cfg(not(feature = "vendor-certs-oob"))]
use caliptra_mcu_libtock_console::Console;
#[cfg(feature = "cert-provisioning")]
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_scratch_alloc::BitmapAllocator;
// `log_warn!` writes through the console writer, so the trait must be in scope;
// the macro compiles to nothing without a log transport, which makes the import
// look unused.
#[allow(unused_imports)]
use core::fmt::Write as _;
#[cfg(not(feature = "vendor-certs-oob"))]
use mcu_caliptra_api::{
    mldsa87_cert_der_len, populate_idev_ecc384_cert, populate_idev_mldsa87_cert,
};
use mcu_caliptra_api::{ScratchAlloc, POPULATE_IDEV_MLDSA87_MAX_CERT_SIZE};
use mcu_error::McuResult;

/// OTP partition ID for the IDevID ECC certificate.
#[cfg(not(feature = "vendor-certs-oob"))]
const OTP_IDEVID_ECC_PARTITION: u32 = 0x01;

/// OTP partition ID for the IDevID ML-DSA-87 certificate.
#[cfg(not(feature = "vendor-certs-oob"))]
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
struct MciTaskCertStore(core::cell::UnsafeCell<Option<TaskCertStore<CertStoreStorage>>>);

// SAFETY: `user-app` runs on a single-threaded Embassy executor and
// `MCI_CERT_STORE` is accessed exclusively from the single `mcu_mbox_task`
// via the MCI-only `MC_GET_CERT_CHAIN_INFO`, `MC_GET_CERT_CHAIN`, and
// `MC_SET_CERT_CHAIN` commands.
#[cfg(feature = "mcu-mbox-service")]
unsafe impl Sync for MciTaskCertStore {}

// Stored as `None` (all-zero niche on `&'static SharedCertStore`) so the
// static resides in `.bss` rather than `.data`.
#[cfg(feature = "mcu-mbox-service")]
static MCI_CERT_STORE: MciTaskCertStore = MciTaskCertStore(core::cell::UnsafeCell::new(None));

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
    #[cfg(not(feature = "vendor-certs-oob"))]
    {
        let (ecc_populated, mldsa_populated) = populate_idev(scratch).await?;
        CERT_STORE.set_idevid_populated(CertificateAlgorithm::EccP384, ecc_populated);
        CERT_STORE.set_idevid_populated(CertificateAlgorithm::MlDsa87, mldsa_populated);
    }
    setup_endorsements(&CERT_STORE, scratch).await?;
    Ok(())
}

pub(crate) fn shared() -> &'static SharedCertStore<CertStoreStorage> {
    &CERT_STORE
}

#[cfg(feature = "mcu-mbox-service")]
pub(crate) fn mci_store() -> &'static TaskCertStore<CertStoreStorage> {
    // SAFETY: single-threaded executor; accessed only from `mcu_mbox_task`.
    unsafe { (*MCI_CERT_STORE.0.get()).get_or_insert_with(|| TaskCertStore::new(&CERT_STORE)) }
}

/// One-time Caliptra setup: read the IDevID certs from OTP and install them,
/// returning `Ok((ecc_populated, mldsa_populated))`.
///
/// Boot initialization invokes this before spawning any mailbox-using task, so
/// the installs cannot contend with an SPDM responder or the MCU mailbox
/// service. ECC-384 is required when present in OTP; ML-DSA-87 remains
/// best-effort until SPDM can negotiate that algorithm.
#[cfg(not(feature = "vendor-certs-oob"))]
async fn populate_idev<A: ScratchAlloc>(alloc: &A) -> McuResult<(bool, bool)> {
    let otp = ExternalOtp::<DefaultSyscalls>::new();
    let ecc_populated =
        populate_idev_cert_from_otp(alloc, &otp, CertificateAlgorithm::EccP384).await?;
    let mldsa_populated =
        match populate_idev_cert_from_otp(alloc, &otp, CertificateAlgorithm::MlDsa87).await {
            Ok(populated) => populated,
            Err(e) => {
                let mut cw = Console::<DefaultSyscalls>::writer();
                crate::log_warn!(
                    cw,
                    "CERT_STORE: ML-DSA-87 IDevID cert not installed: 0x{}",
                    crate::Hex32(u32::from(e))
                );
                false
            }
        };
    Ok((ecc_populated, mldsa_populated))
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
    // Vendor: ReadOnly endorsement (static Root CA in-band, or out-of-band).
    #[cfg(not(feature = "vendor-certs-oob"))]
    store
        .init_readonly_endorsement(
            alloc,
            EndorsementRole::Vendor,
            slot0_endorsements::SLOT0_ECC_ROOT_CERT_CHAIN,
            Some(slot0_endorsements::SLOT0_MLDSA_ROOT_CERT_CHAIN),
        )
        .await?;
    #[cfg(feature = "vendor-certs-oob")]
    store
        .init_oob_endorsement(alloc, EndorsementRole::Vendor, true)
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

#[cfg(not(feature = "vendor-certs-oob"))]
const fn otp_partition(algo: CertificateAlgorithm) -> u32 {
    match algo {
        CertificateAlgorithm::EccP384 => OTP_IDEVID_ECC_PARTITION,
        CertificateAlgorithm::MlDsa87 => OTP_IDEVID_MLDSA_PARTITION,
    }
}

#[cfg(not(feature = "vendor-certs-oob"))]
async fn populate_idev_cert<A: ScratchAlloc>(
    alloc: &A,
    algo: CertificateAlgorithm,
    cert: &[u8],
) -> McuResult<()> {
    match algo {
        CertificateAlgorithm::EccP384 => populate_idev_ecc384_cert(alloc, cert).await,
        CertificateAlgorithm::MlDsa87 => populate_idev_mldsa87_cert(alloc, cert).await,
    }
}

/// Read an IDevID cert from OTP and install it into Caliptra if a valid DER
/// certificate is present in the partition.
///
/// The certificate is staged in scratch and sent as one contiguous payload
/// rather than streamed out of OTP so the Caliptra mailbox lock is held only
/// for the transfer itself.
#[cfg(not(feature = "vendor-certs-oob"))]
async fn populate_idev_cert_from_otp<A: ScratchAlloc>(
    alloc: &A,
    otp: &ExternalOtp<DefaultSyscalls>,
    algo: CertificateAlgorithm,
) -> McuResult<bool> {
    let partition_id = otp_partition(algo);
    let word = otp
        .read(partition_id, 0)
        .await
        .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
    let partition_size = otp
        .partition_size(partition_id)
        .map_err(|_| mcu_error::codes::INTERNAL_BUG)? as usize;
    let Some(cert_size) = mldsa87_cert_der_len(word, partition_size) else {
        return Ok(false);
    };
    let mut cert = alloc.alloc(cert_size)?;
    read_otp_range(otp, partition_id, &mut cert).await?;
    populate_idev_cert(alloc, algo, &cert).await?;
    Ok(true)
}

#[cfg(all(feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
static PROVISION_IDEV_IN_PROGRESS: portable_atomic::AtomicBool =
    portable_atomic::AtomicBool::new(false);

/// Serializes `IDevID` provisioning across transports (`mcu_mbox_task` and
/// `spdm_task`), matching `CertSlot::write_in_progress` for managed slots.
///
/// `ExternalOtp` uses a single upcall subscription per process, and the
/// populated-state check spans `.await` points before marking the certificate
/// populated.
#[cfg(all(feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
struct ProvisionIdevGuard;

#[cfg(all(feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
impl ProvisionIdevGuard {
    fn acquire() -> Result<Self, caliptra_mcu_common_commands::CaliptraCompletionCode> {
        PROVISION_IDEV_IN_PROGRESS
            .compare_exchange(
                false,
                true,
                portable_atomic::Ordering::AcqRel,
                portable_atomic::Ordering::Acquire,
            )
            .map(|_| Self)
            .map_err(|_| caliptra_mcu_common_commands::CaliptraCompletionCode::InvalidState)
    }
}

#[cfg(all(feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
impl Drop for ProvisionIdevGuard {
    fn drop(&mut self) {
        PROVISION_IDEV_IN_PROGRESS.store(false, portable_atomic::Ordering::Release);
    }
}

/// Populate and/or write to external OTP the `IDevID` certificate for `algo`.
#[cfg(all(feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
pub(crate) async fn provision_idevid_cert<A: ScratchAlloc>(
    alloc: &A,
    algo: CertificateAlgorithm,
    write_otp: bool,
    data: &[u8],
) -> Result<(), caliptra_mcu_common_commands::CaliptraCompletionCode> {
    use caliptra_mcu_common_commands::CaliptraCompletionCode;

    let Some(&first_word) = data.first_chunk::<4>() else {
        return Err(CaliptraCompletionCode::InvalidParameter);
    };
    let otp = ExternalOtp::<DefaultSyscalls>::new();
    let partition_id = otp_partition(algo);
    let partition_size = otp
        .partition_size(partition_id)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)? as usize;
    if mldsa87_cert_der_len(u32::from_le_bytes(first_word), partition_size) != Some(data.len()) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let _guard = ProvisionIdevGuard::acquire()?;

    if otp
        .is_partition_locked(partition_id)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?
    {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    if CERT_STORE.is_idevid_populated(algo) {
        if !write_otp {
            return Err(CaliptraCompletionCode::InvalidState);
        }
        // If reset occurred after saving word 0 to OTP but before locking the
        // partition, the next boot loads the cert into Core (`is_idevid_populated == true`)
        // while the partition remains unlocked. Verify that the stored OTP
        // certificate matches `data` and allow completing the lock.
        for (word_idx, chunk) in data.chunks(4).enumerate() {
            let offset = (word_idx * 4) as u32;
            let actual = otp
                .read(partition_id, offset)
                .await
                .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
            if actual.to_le_bytes().get(..chunk.len()) != Some(chunk) {
                return Err(CaliptraCompletionCode::InvalidState);
            }
        }
        otp.lock_partition(partition_id)
            .await
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        return Ok(());
    }

    if write_otp {
        // Write and verify all body words (`offset = 4, 8, ...`) before
        // committing the DER header at `offset = 0` so an interrupted write
        // leaves word 0 erased (`0xFFFF_FFFF`) and does not appear provisioned
        // on reboot.
        for (word_idx, chunk) in data
            .chunks(4)
            .enumerate()
            .skip(1)
            .chain(core::iter::once((0, first_word.as_slice())))
        {
            let offset = (word_idx * 4) as u32;
            let mut word_bytes = [0xFFu8; 4];
            for (dst, &src) in word_bytes.iter_mut().zip(chunk) {
                *dst = src;
            }
            otp.write(partition_id, offset, u32::from_le_bytes(word_bytes))
                .await
                .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
            let actual = otp
                .read(partition_id, offset)
                .await
                .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
            if actual.to_le_bytes().get(..chunk.len()) != Some(chunk) {
                return Err(CaliptraCompletionCode::OperationFailed);
            }
        }
        otp.lock_partition(partition_id)
            .await
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    }

    populate_idev_cert(alloc, algo, data)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    CERT_STORE.set_idevid_populated(algo, true);

    Ok(())
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
#[cfg(not(feature = "vendor-certs-oob"))]
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

#[cfg(all(test, feature = "cert-provisioning", not(feature = "vendor-certs-oob")))]
mod tests {
    use super::ProvisionIdevGuard;
    use caliptra_mcu_common_commands::CaliptraCompletionCode;

    #[test]
    fn provision_idev_guard_rejects_concurrent_acquisition_and_releases_on_drop() {
        let guard = ProvisionIdevGuard::acquire().expect("first acquire should succeed");
        assert_eq!(
            ProvisionIdevGuard::acquire().err(),
            Some(CaliptraCompletionCode::InvalidState)
        );
        drop(guard);
        let _reacquired = ProvisionIdevGuard::acquire().expect("acquire after drop should succeed");
    }
}
