// Licensed under the Apache-2.0 license

//! Integration test for the caliptra-util-host Mailbox validator.
//!
//! This test starts the emulator (hw_model), waits for the mailbox to be ready,
//! then runs a UDP responder on the main thread that bridges between the
//! `caliptra-mailbox-client` Validator (running in a spawned thread) and the
//! hw_model's mailbox API.
//!
//! The UDP protocol is: client sends `[4-byte cmd LE][payload]`, server responds
//! with raw response bytes.
//!
//! The responder uses `start_mailbox_execute` + manual stepping with a large
//! timeout (200M cycles) to support slow crypto operations in the emulator.

#[cfg(test)]
pub mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_api::SocManager;
    use caliptra_mailbox_client::{DebugUnlockKeys, LocalDebugUnlockSigner, Validator};
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_romtime::McuBootMilestones;

    use random_port::PortPicker;
    use std::mem::size_of;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use zerocopy::IntoBytes;

    /// Device ID and vendor ID that the firmware returns.
    /// Must match the values configured in the emulator test firmware.
    const TEST_DEVICE_ID: u16 = 0x0010;
    const TEST_VENDOR_ID: u16 = 0x1414;

    /// Maximum cycles to wait for a mailbox command to complete.
    /// Crypto operations (ECDH, ECDSA, AES, etc.) are slow in the emulator
    /// and need significantly more than the default 40M cycles.
    const MAILBOX_TIMEOUT_CYCLES: u64 = 200_000_000;

    /// Execute a mailbox command with a larger timeout than the default.
    /// Uses `start_mailbox_execute` to send the command, then manually steps
    /// the hw_model until completion or timeout.
    fn mailbox_execute_with_timeout(
        hw: &mut impl McuHwModel,
        cmd: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        hw.start_mailbox_execute(cmd, payload)
            .map_err(|e| format!("start_mailbox_execute failed: {}", e))?;

        // Step until the command finishes or we time out.
        let mut remaining = MAILBOX_TIMEOUT_CYCLES;
        while hw.cmd_status().cmd_busy() {
            hw.step();
            remaining -= 1;
            if remaining == 0 {
                return Err("Mailbox command timed out".to_string());
            }
        }

        let status = hw.cmd_status();

        if status.cmd_failure() {
            hw.mcu_manager().with_mbox0(|mbox| {
                mbox.mbox_execute().write(|w| w.execute(false));
            });
            return Err("Mailbox command failed".to_string());
        }

        hw.mcu_manager().with_mbox0(|mbox| {
            if status.cmd_complete() {
                let dlen = mbox.mbox_dlen().read() as usize;
                if dlen == 0 {
                    mbox.mbox_execute().write(|w| w.execute(false));
                    return Ok(None);
                }
            } else if !status.data_ready() {
                mbox.mbox_execute().write(|w| w.execute(false));
                return Err(format!("Unknown mailbox status {:x}", u32::from(status)));
            }

            let dlen = mbox.mbox_dlen().read() as usize;
            let mut output = Vec::with_capacity(dlen);

            let len_words = dlen / size_of::<u32>();
            for i in 0..len_words {
                let word = mbox.mbox_sram().at(i).read();
                output.extend_from_slice(&word.to_le_bytes());
            }

            let remaining_bytes = dlen % size_of::<u32>();
            if remaining_bytes > 0 {
                let word = mbox.mbox_sram().at(len_words).read();
                output.extend_from_slice(&word.to_le_bytes()[..remaining_bytes]);
            }

            mbox.mbox_execute().write(|w| w.execute(false));
            Ok(Some(output))
        })
    }

    #[ignore]
    #[test]
    fn test_caliptra_util_host_validator() {
        use caliptra_image_fake_keys::{
            VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
            VENDOR_MLDSA_KEY_0_PUBLIC,
        };
        use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let feature = "test-caliptra-util-host-validator";
        let udp_port = PortPicker::new().random(true).pick().unwrap();
        let unlock_level = 1u8;

        // --- Prepare ECC public key in hardware format (big-endian u32 words) ---
        let mut ecc_pub_key_u32 = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
        ecc_pub_key_u32[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecc_pub_key_u32[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
        let ecc_pub_key_bytes: [u8; 96] = ecc_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Prepare MLDSA public key in hardware format (little-endian u32 words) ---
        let mldsa_pub_key_raw = VENDOR_MLDSA_KEY_0_PUBLIC.0.as_bytes();
        let mldsa_pub_key_u32: Vec<u32> = mldsa_pub_key_raw
            .chunks(4)
            .map(|chunk| {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                u32::from_le_bytes(arr)
            })
            .collect();
        let mldsa_pub_key_bytes: [u8; 2592] = mldsa_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Set up keypairs for fuse provisioning ---
        let mut prod_dbg_keypairs: Vec<([u8; 96], [u8; 2592])> = vec![([0u8; 96], [0u8; 2592]); 8];
        prod_dbg_keypairs[(unlock_level - 1) as usize] = (ecc_pub_key_bytes, mldsa_pub_key_bytes);

        // --- Prepare ECC private key bytes for signing ---
        let mut be_ecc_priv_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
        for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
            be_ecc_priv_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        // --- Prepare MLDSA private key bytes for signing ---
        let mldsa_priv_key_bytes: Vec<u8> = VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec();

        // --- Build DebugUnlockKeys and LocalDebugUnlockSigner to pass to the validator ---
        let debug_unlock_keys = DebugUnlockKeys {
            ecc_private_key_bytes: be_ecc_priv_key_bytes,
            ecc_public_key: ecc_pub_key_u32,
            mldsa_private_key_bytes: mldsa_priv_key_bytes,
            mldsa_public_key: <[u32; 648]>::try_from(mldsa_pub_key_u32.as_slice()).unwrap(),
        };
        let debug_unlock_signer = LocalDebugUnlockSigner::new(debug_unlock_keys);

        // --- Start hw_model with keys provisioned in fuses ---
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            debug_intent: true,
            lifecycle_controller_state: Some(caliptra_mcu_hw_model::LifecycleControllerState::Prod),
            prod_dbg_unlock_keypairs: prod_dbg_keypairs,
            ..Default::default()
        });

        // Wait for the firmware mailbox to be ready.
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        // Bind the UDP responder socket on the main thread.
        let bind_addr = format!("127.0.0.1:{}", udp_port);
        let socket = UdpSocket::bind(&bind_addr).expect("Failed to bind UDP responder socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("Failed to set socket read timeout");

        println!("Mailbox responder listening on {}", bind_addr);

        // Flag for the validator thread to signal completion.
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let validator_failed = Arc::new(AtomicBool::new(false));
        let validator_failed_clone = validator_failed.clone();

        // Spawn the validator client in a background thread.
        let validator_handle = std::thread::spawn(move || {
            let server_addr = format!("127.0.0.1:{}", udp_port)
                .parse()
                .expect("Failed to parse server address");
            let validator = Validator::with_expected_values(
                server_addr,
                Some(TEST_DEVICE_ID),
                Some(TEST_VENDOR_ID),
            )
            .set_recv_timeout(Duration::from_secs(120))
            .set_verbose(true)
            .set_debug_unlock_signer(Box::new(debug_unlock_signer));

            println!("Running Mailbox validator in-process (port={})", udp_port);

            match validator.start() {
                Ok(results) => {
                    let all_passed = results.iter().all(|r| r.passed);
                    if all_passed {
                        println!("✓ Caliptra Mailbox validator PASSED");
                    } else {
                        println!("✗ Caliptra Mailbox validator FAILED");
                        for r in &results {
                            if !r.passed {
                                println!("  FAIL: {} — {:?}", r.test_name, r.error_message);
                            }
                        }
                        validator_failed_clone.store(true, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    println!("✗ Caliptra Mailbox validator error: {:#}", e);
                    validator_failed_clone.store(true, Ordering::Relaxed);
                }
            }

            done_clone.store(true, Ordering::Relaxed);
        });

        // Main-thread responder loop: receive UDP commands from the validator,
        // forward them to the hw_model mailbox, and send responses back.
        let mut buf = [0u8; 16 * 1024];
        while !done.load(Ordering::Relaxed) {
            let (bytes_received, client_addr) = match socket.recv_from(&mut buf) {
                Ok(result) => result,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut
                    {
                        continue;
                    }
                    panic!("UDP recv error: {}", e);
                }
            };

            if bytes_received < 4 {
                println!(
                    "Received too-short packet ({} bytes), ignoring",
                    bytes_received
                );
                continue;
            }

            let cmd = u32::from_le_bytes(buf[..4].try_into().unwrap());
            let payload = &buf[4..bytes_received];

            println!(
                "<<< Responder: forwarding cmd 0x{:08x} ({} bytes payload)",
                cmd,
                payload.len()
            );

            // For prod debug unlock commands, set the prod_dbg_unlock_req bit
            // in the SoC IFC register before forwarding the command.
            // This simulates what the SoC would do in a real debug unlock flow.
            const MC_PROD_DEBUG_UNLOCK_REQ: u32 = 0x4D50_5552;
            const MC_PROD_DEBUG_UNLOCK_TOKEN: u32 = 0x4D50_5554;
            if cmd == MC_PROD_DEBUG_UNLOCK_REQ || cmd == MC_PROD_DEBUG_UNLOCK_TOKEN {
                hw.caliptra_soc_manager()
                    .soc_ifc()
                    .ss_dbg_manuf_service_reg_req()
                    .write(|w| w.prod_dbg_unlock_req(true));
            }

            let response_data = match mailbox_execute_with_timeout(&mut hw, cmd, payload) {
                Ok(Some(data)) => data,
                Ok(None) => vec![],
                Err(e) => {
                    println!(">>> Responder: mailbox error: {}", e);
                    vec![]
                }
            };

            println!(
                ">>> Responder: sending {} bytes response",
                response_data.len()
            );
            socket
                .send_to(&response_data, client_addr)
                .expect("Failed to send UDP response");
        }

        validator_handle.join().expect("Validator thread panicked");
        assert!(
            !validator_failed.load(Ordering::Relaxed),
            "Mailbox validator reported failures"
        );

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
