// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::jtag::test::{debug_is_unlocked, ss_setup};

    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_image_fake_keys::{
        VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
        VENDOR_MLDSA_KEY_0_PUBLIC,
    };
    use caliptra_image_types::{
        ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE, MLDSA87_PRIV_KEY_BYTE_SIZE,
    };
    use mcu_hw_model::debug_unlock::{
        prod_debug_unlock_gen_signed_token, prod_debug_unlock_get_challenge,
        prod_debug_unlock_send_request, prod_debug_unlock_send_token,
        prod_debug_unlock_wait_for_in_progress,
    };
    use romtime::LifecycleControllerState;

    use fips204::ml_dsa_87::PrivateKey as MldsaPrivateKey;
    use fips204::traits::SerDes;
    use p384::SecretKey as EcdsaSecretKey;
    use zerocopy::IntoBytes;

    #[test]
    fn test_prod_debug_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Prod),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ true,
            /*enable_mcu_uart_log=*/ true,
        );

        // Connect to Caliptra Core JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        println!("Connecting to Core TAP ...");
        let mut core_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraCoreTap)
            .expect("Failed to connect to the Caliptra Core JTAG TAP.");
        println!("Connected.");
        println!("Connecting to MCU TAP ...");
        let mut mcu_tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::CaliptraMcuTap)
            .expect("Failed to connect to the Caliptra MCU JTAG TAP.");
        println!("Connected.");

        // Confirm debug is locked.
        let is_unlocked = debug_is_unlocked(&mut *core_tap, &mut *mcu_tap).unwrap_or(false);
        assert_eq!(is_unlocked, false);

        // Ensure another prod debug unlock operation is not in progress.
        let dbg_manuf_service_rsp = core_tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp)
            .expect("Unable to read SsDbgManufServiceRegRes reg.");
        assert_eq!(dbg_manuf_service_rsp & 0x20, 0);
        let mut dbg_manuf_service_req = core_tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq)
            .expect("Unable to read SsDbgManufServiceRegReq reg.");
        assert_eq!(dbg_manuf_service_req, 0);

        // Request prod debug unlock operation.
        println!("Request to initiate prod debug unlock ...");
        core_tap
            .write_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq, 0x2)
            .expect("Unable to write SsDbgManufServiceRegReq reg.");
        dbg_manuf_service_req = core_tap
            .read_reg(&CaliptraCoreReg::SsDbgManufServiceRegReq)
            .expect("Unable to read SsDbgManufServiceRegReq reg.");
        assert_eq!(dbg_manuf_service_req, 0x2);
        println!("Request sent.");

        // Continue Caliptra Core boot.
        core_tap
            .write_reg(&CaliptraCoreReg::BootfsmGo, 0x1)
            .expect("Unable to write BootfsmGo.");

        // Wait for the Caliptra mailbox to become available.
        let mut mb_available = false;
        println!("Waiting for Caliptra mailbox TAP to become available ...");
        while let Ok(rsp) = core_tap.read_reg(&CaliptraCoreReg::SsDbgManufServiceRegRsp) {
            if rsp & 0x200 != 0 {
                mb_available = true;
                break;
            }
            println!("waiting {:x?} ...", rsp);
            model.base.step();
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(mb_available, true);
        println!("Mailbox available.");

        // Wait for the prod debug unlock request to be "in-progress".
        println!("Waiting for prod debug unlock in progress ...");
        let _ = prod_debug_unlock_wait_for_in_progress(
            &mut model,
            &mut *core_tap,
            /*begin=*/ true,
        );
        println!("In progress.");

        // Send the debug unlock request and wait for the challenge response in the mailbox.
        println!("Sending the prod debug unlock request ...");
        prod_debug_unlock_send_request(&mut *core_tap, /*debug_level=*/ 1)
            .expect("Failed to send prod debug unlock request.");
        model.base.step();
        println!("Request sent.");
        let du_challenge = prod_debug_unlock_get_challenge(&mut *core_tap)
            .expect("Unable to read challenge in mailbox.");
        model.base.step();
        println!("Challenge received.");

        // Load the ECDSA private key to sign the token with.
        let mut be_ecc_priv_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
        for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
            be_ecc_priv_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        let ecc_private_key = EcdsaSecretKey::from_slice(&be_ecc_priv_key_bytes)
            .expect("Unable to load ECC P384 private key.");
        let mut ecc_public_key = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
        ecc_public_key[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecc_public_key[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);

        // Load the ML-DSA private key to sign the token with.
        let mldsa_priv_key_bytes: [u8; MLDSA87_PRIV_KEY_BYTE_SIZE] = VENDOR_MLDSA_KEY_0_PRIVATE
            .0
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key size"))
            .expect("Unable to load ML-DSA-87 private key.");
        let mldsa_private_key = MldsaPrivateKey::try_from_bytes(mldsa_priv_key_bytes)
            .expect("Unable to load ML-DSA-87 private key.");

        // Construct the debug unlock token.
        println!("Constructing the signed unlock token ...");
        let du_token = prod_debug_unlock_gen_signed_token(
            &du_challenge,
            /*debug_level=*/ 1,
            &ecc_private_key,
            &mldsa_private_key,
            &ecc_public_key,
            &VENDOR_MLDSA_KEY_0_PUBLIC.0,
        )
        .expect("Unable to generate a signed token.");
        println!("Token constructing and signed.");

        // Send the signed prod debug unlock token to the mailbox.
        println!("Sending the signed unlock token to the mailbox ...");
        prod_debug_unlock_send_token(&mut *core_tap, &du_token)
            .expect("Unable to send the signed token to the mailbox.");
        model.base.step();
        println!("Token sent.");

        // Wait for the prod debug unlock request to be complete.
        println!("Waiting for prod debug unlock in progress to complete ...");
        let response = prod_debug_unlock_wait_for_in_progress(
            &mut model,
            &mut *core_tap,
            /*begin=*/ false,
        );
        assert_eq!(response & 0x8, 0x8);
        println!("Unlock complete.");

        // Confirm debug is unlocked.
        core_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine CPU target.");
        core_tap
            .set_sysbus_access()
            .expect("Failed to set sysbus access.");
        mcu_tap
            .reexamine_cpu_target()
            .expect("Failed to reexamine CPU target.");
        mcu_tap
            .set_sysbus_access()
            .expect("Failed to set sysbus access.");
        let is_unlocked = debug_is_unlocked(&mut *core_tap, &mut *mcu_tap).unwrap_or(false);
        assert_eq!(is_unlocked, true);
    }
}
