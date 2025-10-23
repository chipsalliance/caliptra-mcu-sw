// Licensed under the Apache-2.0 license
use caliptra_api::mailbox::{FwInfoResp, GetImageInfoResp};
use core::fmt::Write;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::evidence::device_state::*;
use libapi_caliptra::evidence::pcr_quote::{PcrQuote, PCR_QUOTE_BUFFER_SIZE};
use romtime::{println, test_exit};

#[allow(unused)]
pub(crate) async fn test_get_pcr_quote() {
    println!("==Starting PCR quote test==");
    test_pcr_quote_with_pqc_signature().await;
    test_pcr_quote_with_ecc_signature().await;
    println!("==PCR Quote test success==");
}

async fn test_pcr_quote_with_pqc_signature() {
    println!("Starting PCR quote with PQC signature test");
    let mut pcr_quote = [0u8; PCR_QUOTE_BUFFER_SIZE];

    match PcrQuote::pcr_quote(None, &mut pcr_quote, true).await {
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

async fn test_pcr_quote_with_ecc_signature() {
    println!("Starting PCR quote with ECC signature test");
    let mut pcr_quote = [0u8; PCR_QUOTE_BUFFER_SIZE];

    match PcrQuote::pcr_quote(None, &mut pcr_quote, false).await {
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

pub async fn test_get_pcrs() {
    println!("==Starting get PCRs test==");
    let pcrs = match PcrQuote::get_pcrs().await {
        Ok(pcrs) => pcrs,
        Err(err) => {
            println!("Failed to get the PCRs. {:?}", err);
            test_exit(1);
        }
    };
    for (i, pcr) in pcrs.iter().enumerate() {
        println!("PCR[{}]: {:02x?}", i, pcr);
    }
    println!("==Get PCRs test success==");
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
