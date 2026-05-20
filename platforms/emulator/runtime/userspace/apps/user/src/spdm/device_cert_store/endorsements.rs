// Licensed under the Apache-2.0 license

use crate::spdm::cert_store::cert_chain::{
    EndorsementCertChainTrait, MutableEndorsement, ReadOnlyEndorsement,
};
use caliptra_mcu_spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, MAX_CERT_SLOTS_SUPPORTED,
};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

static mut SLOT0_ENDORSEMENT: MaybeUninit<ReadOnlyEndorsement> = MaybeUninit::uninit();
static SLOT0_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut SLOT1_ENDORSEMENT: MaybeUninit<MutableEndorsement> = MaybeUninit::uninit();
static SLOT1_INITIALIZED: AtomicBool = AtomicBool::new(false);

static mut SLOT2_ENDORSEMENT: MaybeUninit<MutableEndorsement> = MaybeUninit::uninit();
static SLOT2_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub async fn init_readonly_slot() -> CertStoreResult<&'static mut dyn EndorsementCertChainTrait> {
    if SLOT0_INITIALIZED.load(Ordering::Acquire) {
        unsafe {
            return Ok(SLOT0_ENDORSEMENT.assume_init_mut() as &mut dyn EndorsementCertChainTrait);
        }
    }

    let endorsement_chain = ReadOnlyEndorsement::new(0).await?;

    unsafe {
        if SLOT0_INITIALIZED.load(Ordering::Acquire) {
            return Ok(SLOT0_ENDORSEMENT.assume_init_mut() as &mut dyn EndorsementCertChainTrait);
        }

        SLOT0_ENDORSEMENT.write(endorsement_chain);
        SLOT0_INITIALIZED.store(true, Ordering::Release);
        Ok(SLOT0_ENDORSEMENT.assume_init_mut() as &mut dyn EndorsementCertChainTrait)
    }
}

pub fn init_mutable_slot(
    slot_id: u8,
) -> CertStoreResult<&'static mut dyn EndorsementCertChainTrait> {
    match slot_id {
        1 => unsafe {
            if !SLOT1_INITIALIZED.load(Ordering::Acquire) {
                SLOT1_ENDORSEMENT.write(MutableEndorsement::new(1));
                SLOT1_INITIALIZED.store(true, Ordering::Release);
            }
            Ok(SLOT1_ENDORSEMENT.assume_init_mut() as &mut dyn EndorsementCertChainTrait)
        },
        2 => unsafe {
            if !SLOT2_INITIALIZED.load(Ordering::Acquire) {
                SLOT2_ENDORSEMENT.write(MutableEndorsement::new(2));
                SLOT2_INITIALIZED.store(true, Ordering::Release);
            }
            Ok(SLOT2_ENDORSEMENT.assume_init_mut() as &mut dyn EndorsementCertChainTrait)
        },
        _ => Err(CertStoreError::InvalidSlotId),
    }
}

pub async fn collect_endorsement_readers() -> CertStoreResult<
    [Option<&'static mut dyn EndorsementCertChainTrait>; MAX_CERT_SLOTS_SUPPORTED as usize],
> {
    Ok([
        Some(init_readonly_slot().await?),
        Some(init_mutable_slot(1)?),
        Some(init_mutable_slot(2)?),
    ])
}
