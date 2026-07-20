// Licensed under the Apache-2.0 license
use caliptra_mcu_attestation_evidence::pcr_quote::{
    encode_pcr_quote, PcrQuoteAlgorithm, PCR_QUOTE_MAX_SIZE,
};
use caliptra_mcu_libapi_caliptra::evidence::device_state::*;
use caliptra_mcu_romtime::{println, test_exit};
use caliptra_mcu_spdm_pal::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use core::ptr::NonNull;

const PCR_QUOTE_SCRATCH_SIZE: usize = 8192;
const PCR_QUOTE_SCRATCH_SLOTS: usize = PCR_QUOTE_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct PcrQuoteScratchSlot([u8; BITMAP_SLOT_SIZE]);

static PCR_QUOTE_ALLOCATOR: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
static mut PCR_QUOTE_SCRATCH: [PcrQuoteScratchSlot; PCR_QUOTE_SCRATCH_SLOTS] =
    [PcrQuoteScratchSlot([0; BITMAP_SLOT_SIZE]); PCR_QUOTE_SCRATCH_SLOTS];
static mut PCR_QUOTE_BUFFER: [u8; PCR_QUOTE_MAX_SIZE] = [0; PCR_QUOTE_MAX_SIZE];

pub(crate) fn init_pcr_quote_allocator() -> &'static BitmapAllocator {
    let scratch_ptr =
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!(PCR_QUOTE_SCRATCH).cast::<u8>()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);
    unsafe { PCR_QUOTE_ALLOCATOR.init_once(scratch_ptr, PCR_QUOTE_SCRATCH_SIZE) }
}

#[allow(unused)]
pub(crate) async fn test_get_pcr_quote(alloc: &BitmapAllocator) {
    println!("==Starting PCR quote test==");
    test_pcr_quote_with_pqc_signature(alloc).await;
    test_pcr_quote_with_ecc_signature(alloc).await;
    println!("==PCR Quote test success==");
}

async fn test_pcr_quote_with_pqc_signature(alloc: &BitmapAllocator) {
    println!("Starting PCR quote with PQC signature test");
    let pcr_quote = unsafe { &mut PCR_QUOTE_BUFFER };
    pcr_quote.fill(0);

    match encode_pcr_quote(alloc, PcrQuoteAlgorithm::Mldsa87, None, pcr_quote).await {
        Ok(copy_len) if copy_len > 0 => {
            println!(
                "PCR quote with PQC Signature[{}]: {:x?} ",
                copy_len,
                &pcr_quote[..copy_len]
            );
        }
        Err(err) => {
            println!("Failed to get PCR quote: {:?}", err);
            test_exit(1);
        }
        _ => {
            println!("Failed! Got empty PCR Quote");
            test_exit(1);
        }
    }

    println!("PCR Quote with PQC signature test success");
}

async fn test_pcr_quote_with_ecc_signature(alloc: &BitmapAllocator) {
    println!("Starting PCR quote with ECC signature test");
    let pcr_quote = unsafe { &mut PCR_QUOTE_BUFFER };
    pcr_quote.fill(0);

    match encode_pcr_quote(alloc, PcrQuoteAlgorithm::Ecc384, None, pcr_quote).await {
        Ok(copy_len) if copy_len > 0 => {
            println!(
                "PCR quote with ECC Signature[{}]: {:x?}",
                copy_len,
                &pcr_quote[..copy_len]
            );
        }
        Err(err) => {
            println!("Failed to get PCR quote: {:?}", err);
            test_exit(1);
        }
        _ => {
            println!("Failed! Got empty PCR Quote");
            test_exit(1);
        }
    }

    println!("PCR Quote ECC signature test success");
}

pub async fn test_get_fw_info() {
    println!("==Starting get FW_INFO test==");
    let fw_info = match DeviceState::fw_info().await {
        Ok(fw_info) => fw_info,
        Err(err) => {
            println!("Failed to get the FW_INFO. {:?}", err);
            test_exit(1);
        }
    };

    println!("FW_NFO: {:?}", fw_info);
    println!("==Get FW_INFO test success==");
}

pub async fn test_get_image_info() {
    println!("==Starting get IMAGE_INFO test==");
    // Example: Get image info for MCU firmware (fw_id = 0x02)
    let mcu_fw_id: u32 = 0x02;
    let mcu_image_info = match DeviceState::image_info(mcu_fw_id).await {
        Ok(image_info) => image_info,
        Err(err) => {
            println!("Failed to get image info for id {}: {:?}", mcu_fw_id, err);
            test_exit(1);
        }
    };

    println!(
        "Image info of fw with ID [{}] : {:?}",
        mcu_fw_id, mcu_image_info
    );
    println!("==Get IMAGE_INFO test success==");
}

pub async fn test_get_fw_version() {
    println!("==Starting get FW_VERSION test==");
    let (received_hw_rev, received_rom_version, received_fmc_version, received_rt_version) =
        match DeviceState::fw_version().await {
            Ok(version) => version,
            Err(err) => {
                println!("Failed to get the HW_VERSION. {:?}", err);
                test_exit(1);
            }
        };

    println!(
        "HW_REV: {:x}, ROM_VERSION: {:x}, FMC_VERSION: {:x}, RT_VERSION: {:x}",
        received_hw_rev, received_rom_version, received_fmc_version, received_rt_version
    );
    println!("==Get FW_VERSION test success==");
}
