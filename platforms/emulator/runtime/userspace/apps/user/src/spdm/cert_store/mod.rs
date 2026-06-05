// Licensed under the Apache-2.0 license

//! Cert store initialization for the spdm-lite emulator platform.
//!
//! Reads the IDevID ECC-384 certificate from OTP, installs it into
//! Caliptra, and configures the cert slots:
//!   - Slot 0 (Vendor): ReadOnly endorsement from static Root CA
//!   - Slot 1 (Owner):  Managed endorsement (flash-backed, initially empty)
//!   - Slot 2 (Tenant): Managed endorsement (flash-backed, initially empty)

mod endorsement_certs;

#[cfg(feature = "test-mctp-spdm-set-certificate")]
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use mcu_caliptra_api_lite::{populate_idev_ecc384_cert, ApiAlloc};
use mcu_error::McuResult;
use mcu_spdm_lite_pal::cert::store::SharedCertStore;

/// SPDM slot IDs for OCP PKI entities.
#[allow(dead_code)]
const VENDOR_SPDM_SLOT: u8 = 0;
#[allow(dead_code)]
const OWNER_SPDM_SLOT: u8 = 2;
#[allow(dead_code)]
const TENANT_SPDM_SLOT: u8 = 3;

/// IDevID ECC cert size in OTP partition 1.
const ECC_DEVID_CERT_SIZE: usize = 547;

/// OTP partition ID for the IDevID ECC certificate.
const OTP_IDEVID_ECC_PARTITION: u32 = 0x01;

#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_COUNT: usize = 2;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MANAGED_SLOT_REGION_SIZE: usize = CERT_STORE_PARTITION.size / MANAGED_SLOT_COUNT;

/// Initialize the cert store for all 3 slots.
///
/// Must be called once before SPDM responder tasks start.
/// Slot 0 failure is fatal. Slots 1-2 stay unprovisioned if
/// flash is empty (they'll be provisioned via SET_CERTIFICATE).
/// One-time Caliptra setup: read IDevID from OTP and install.
pub async fn populate_idev<A: ApiAlloc>(alloc: &A) -> McuResult<()> {
    populate_idev_from_otp(alloc).await
}

/// Configure endorsement chains on the shared cert store.
/// Called once from spdm_task before spawning responders.
pub async fn setup_endorsements<A: ApiAlloc>(store: &SharedCertStore, alloc: &A) -> McuResult<()> {
    // Slot 0 (Vendor): ReadOnly endorsement with static Root CA.
    // Retry on mailbox busy (SHA calls during root cert hashing).
    loop {
        match store
            .set_endorsement_chain(
                alloc,
                0,
                endorsement_certs::SLOT0_ECC_ROOT_CERT_CHAIN,
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
        if let Some(slot) = cert_buf
            .get_mut(offset as usize..)
            .and_then(|s| s.first_chunk_mut::<4>())
        {
            *slot = word.to_le_bytes();
        }
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
