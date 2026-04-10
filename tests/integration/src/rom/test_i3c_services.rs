// Licensed under the Apache-2.0 license

//! Integration tests for the ROM I3C services mailbox handler.
//!
//! These tests verify that the ROM I3C services loop correctly processes
//! commands received over the I3C TTI interface.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::Ordering;

    use caliptra_mcu_romtime::McuRomBootStatus;

    const I3C_SERVICES_READY_CHECKPOINT: u16 = McuRomBootStatus::I3cServicesReady as u16;

    /// Step the model until the ROM sets the I3cServicesReady boot checkpoint.
    /// This ensures the ROM has completed IBI announcement and is actively
    /// polling for packets before we send any.
    fn wait_for_i3c_ready(hw: &mut impl McuHwModel) {
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.mci_boot_checkpoint() >= I3C_SERVICES_READY_CHECKPOINT
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 60
        });
        assert!(
            hw.mci_boot_checkpoint() >= I3C_SERVICES_READY_CHECKPOINT,
            "ROM did not enter I3C services mode within timeout (checkpoint: {})",
            hw.mci_boot_checkpoint()
        );
    }

    /// Boot into I3C services, connect, and send a packetized command. Returns
    /// the hw model output after sending. `cmd` is the command byte and
    /// `payload` is the payload (without the command byte).
    fn boot_and_send_i3c_cmd(cmd: u8, payload: &[u8], expected_output: &str) -> String {
        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(stream);

        // Wait for ROM to enter I3C services mode before sending packets.
        // On FPGA the initial IBI can block for tens of ms; packets arriving
        // during that window overflow the 256-byte RX data FIFO.
        wait_for_i3c_ready(&mut hw);

        stream.send_packetized_write(target_addr, cmd, payload);

        hw.output().set_search_term(expected_output);
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 120, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        drop(stream);
        output_text
    }

    /// Boot into I3C services with DOT flash configured so DOT commands
    /// are available. Uses force_i3c_services + test-i3c-services feature.
    fn boot_and_send_i3c_cmd_with_dot(cmd: u8, payload: &[u8], expected_output: &str) -> String {
        use caliptra_mcu_rom_common::DOT_BLOB_SIZE;

        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let dot_flash = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            dot_flash_initial_contents: Some(dot_flash),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(stream);

        wait_for_i3c_ready(&mut hw);

        stream.send_packetized_write(target_addr, cmd, payload);

        hw.output().set_search_term(expected_output);
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 120, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        drop(stream);
        output_text
    }

    /// Test that the ROM enters I3C services mode and responds to PING.
    #[test]
    fn test_i3c_services_ping() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let output = boot_and_send_i3c_cmd(0x00, &[], "[mcu-rom-i3c-svc] PING received");
        assert!(
            output.contains("[mcu-rom-i3c-svc] PING received"),
            "PING was not received by I3C services handler"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that the ROM responds with INVALID_CMD for unknown commands.
    #[test]
    fn test_i3c_services_unknown_cmd() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let output = boot_and_send_i3c_cmd(0xFF, &[], "[mcu-rom-i3c-svc] Unknown command: 0xff");
        assert!(
            output.contains("[mcu-rom-i3c-svc] Unknown command: 0xff"),
            "Unknown command was not logged"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that DOT_STATUS returns DOT fuse state when DOT context is available.
    #[test]
    fn test_i3c_services_dot_status() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let output =
            boot_and_send_i3c_cmd_with_dot(0x01, &[], "[mcu-rom-i3c-svc] DOT_STATUS received");
        assert!(
            output.contains("[mcu-rom-i3c-svc] DOT_STATUS received"),
            "DOT_STATUS was not handled by I3C services handler"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that DOT_RECOVERY with a too-small payload returns INVALID_PAYLOAD.
    #[test]
    fn test_i3c_services_dot_recovery_invalid_payload() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        // Send DOT_RECOVERY (0x02) with only a few bytes of payload
        let output = boot_and_send_i3c_cmd_with_dot(
            0x02,
            &[0x00, 0x01],
            "[mcu-rom-i3c-svc] DOT_RECOVERY payload too small",
        );
        assert!(
            output.contains("[mcu-rom-i3c-svc] DOT_RECOVERY payload too small"),
            "DOT_RECOVERY should reject small payloads"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that DOT_OVERRIDE without a prior DOT_UNLOCK_CHALLENGE returns error.
    #[test]
    fn test_i3c_services_dot_override_without_challenge() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        // Construct a minimal DOT_OVERRIDE payload (won't be processed
        // because no challenge was issued first).
        let payload = vec![0u8; 96 + 96 + 2592 + 4628];

        let output = boot_and_send_i3c_cmd_with_dot(
            0x04,
            &payload,
            "[mcu-rom-i3c-svc] DOT_OVERRIDE without prior challenge",
        );
        assert!(
            output.contains("[mcu-rom-i3c-svc] DOT_OVERRIDE without prior challenge"),
            "DOT_OVERRIDE should fail without prior challenge"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Full DOT_OVERRIDE flow over I3C: challenge/response with ECDSA + MLDSA.
    ///
    /// 1. Boot with locked DOT fuses and vendor PK hash in OTP
    /// 2. Send DOT_UNLOCK_CHALLENGE with vendor public keys
    /// 3. Receive challenge from ROM via IBI
    /// 4. Sign challenge with both ECDSA P-384 and MLDSA-87
    /// 5. Send DOT_OVERRIDE with public keys and signatures
    /// 6. Verify ROM logs success
    #[test]
    #[cfg_attr(
        feature = "fpga_realtime",
        ignore = "FPGA does not support otp_memory provisioning for DOT fuses"
    )]
    fn test_i3c_services_dot_override_full_flow() {
        use caliptra_mcu_rom_common::DOT_BLOB_SIZE;
        use ecdsa::signature::hazmat::PrehashSigner;
        use fips204::traits::Signer;
        use p384::ecdsa::SigningKey;
        use sha2::{Digest, Sha384};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        // Generate random vendor ECC P-384 and MLDSA-87 key pairs
        let (vendor_pub_x, vendor_pub_y, vendor_priv_bytes) = generate_random_ecc_keys();
        let (mldsa_pub, mldsa_priv) = generate_random_mldsa_keys();

        // Compute vendor PK hash for OTP fuses
        let vendor_pk_hash = compute_recovery_pk_hash(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);

        let i3c_port = PortPicker::new().random(true).pick().unwrap();
        let dot_flash = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            dot_flash_initial_contents: Some(dot_flash),
            otp_memory: Some(create_challenge_recovery_otp_memory(&vendor_pk_hash)),
            ..Default::default()
        });

        hw.start_i3c_controller();
        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let tcp = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(tcp);

        wait_for_i3c_ready(&mut hw);

        // Step 1: Build and send DOT_UNLOCK_CHALLENGE (cmd 0x03)
        // Payload: ECC PK X (48) + ECC PK Y (48) + MLDSA PK (2592)
        let mut challenge_payload = Vec::new();
        challenge_payload.extend_from_slice(&vendor_pub_x);
        challenge_payload.extend_from_slice(&vendor_pub_y);
        challenge_payload.extend_from_slice(&mldsa_pub);
        let mldsa_expected = 2592;
        if mldsa_pub.len() < mldsa_expected {
            challenge_payload.resize(
                challenge_payload.len() + mldsa_expected - mldsa_pub.len(),
                0,
            );
        }

        stream.send_packetized_write(target_addr, 0x03, &challenge_payload);

        // Step 2: Read the challenge via private read. The ROM queues the
        // response (status + 48-byte challenge) via the TX descriptor path.
        // The I3C controller thread pushes it to the socket automatically.
        let start = std::time::Instant::now();

        // First wait for the ROM to process the command and log the challenge.
        hw.output()
            .set_search_term("[mcu-rom-i3c-svc] Challenge sent, waiting for DOT_OVERRIDE");
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });
        // Step a bit more to let the I3C controller thread forward the TX response
        let flush = hw.cycle_count() + 100_000;
        hw.step_until(|m| m.cycle_count() >= flush);

        assert_eq!(
            hw.mci_fw_fatal_error(),
            None,
            "ROM hit fatal error during challenge"
        );

        // Read the challenge response via private read from the I3C socket.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let challenge_data = stream
            .receive_private_read(target_addr)
            .expect("Could not obtain challenge response via private read");
        assert!(challenge_data.len() >= 49, "Response too short");
        assert_eq!(challenge_data[0], 0x00, "Expected SUCCESS status");

        let challenge: [u8; 48] = challenge_data[1..49].try_into().unwrap();

        // Step 3: Sign the challenge with vendor keys
        let challenge_hash: [u8; 48] = {
            let mut hasher = Sha384::new();
            hasher.update(&challenge);
            hasher.finalize().into()
        };
        let vendor_secret =
            p384::SecretKey::from_slice(&vendor_priv_bytes).expect("Invalid vendor private key");
        let signing_key = SigningKey::from(&vendor_secret);
        let ecc_sig: p384::ecdsa::Signature = signing_key
            .sign_prehash(&challenge_hash)
            .expect("ECDSA signing failed");
        let ecc_r: [u8; 48] = ecc_sig.r().to_bytes().into();
        let ecc_s: [u8; 48] = ecc_sig.s().to_bytes().into();

        let mldsa_sig = mldsa_priv
            .try_sign_with_seed(&[0u8; 32], &challenge, &[])
            .expect("MLDSA signing failed");
        let mldsa_sig_bytes = mldsa_sig.to_vec();

        // Step 4: Build and send DOT_OVERRIDE (cmd 0x04)
        // Payload: ECC PK (96) + ECC sig (96) + MLDSA PK (2592) + MLDSA sig (4628)
        let mut override_payload = Vec::new();
        override_payload.extend_from_slice(&vendor_pub_x);
        override_payload.extend_from_slice(&vendor_pub_y);
        override_payload.extend_from_slice(&ecc_r);
        override_payload.extend_from_slice(&ecc_s);
        override_payload.extend_from_slice(&mldsa_pub);
        if mldsa_pub.len() < mldsa_expected {
            override_payload.resize(override_payload.len() + mldsa_expected - mldsa_pub.len(), 0);
        }
        let mldsa_sig_expected = 4628;
        override_payload.extend_from_slice(&mldsa_sig_bytes);
        if mldsa_sig_bytes.len() < mldsa_sig_expected {
            override_payload.resize(
                override_payload.len() + mldsa_sig_expected - mldsa_sig_bytes.len(),
                0,
            );
        }

        stream.send_packetized_write(target_addr, 0x04, &override_payload);

        // Step 5: Wait for ROM to verify and complete override
        hw.output()
            .set_search_term("[mcu-rom-i3c-svc] DOT override complete");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(
            output_text.contains("[mcu-rom-i3c-svc] DOT override complete"),
            "DOT override did not complete successfully"
        );
        assert!(
            output_text.contains("[mcu-rom-i3c-svc] Both signatures verified"),
            "Signature verification not logged"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that the handler recovers from a corrupted multi-packet sequence
    /// and can still process a subsequent valid command.
    ///
    /// Sends a multi-packet DOT_RECOVERY with a bad sequence number in the
    /// middle, then sends a valid PING. The handler should discard the broken
    /// reassembly and respond to the PING.
    #[test]
    fn test_i3c_services_error_mid_packet_then_recover() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(stream);

        wait_for_i3c_ready(&mut hw);

        // Send first packet of a multi-packet DOT_RECOVERY (cmd=0x02)
        // with total_seqs=3 but only send seq=0, then inject seq=2
        // (skipping seq=1) to trigger reassembly reset.
        let mut pkt0 = vec![0x02u8, 100, 0, 3];
        pkt0.extend_from_slice(&[0u8; 100]);
        stream.send_private_write(target_addr, pkt0);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Send seq=2 (skipping seq=1) — triggers sequence mismatch
        let mut pkt2 = vec![0x02u8, 100, 2, 3];
        pkt2.extend_from_slice(&[0u8; 100]);
        stream.send_private_write(target_addr, pkt2);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Now send a valid PING command — handler should recover
        stream.send_packetized_write(target_addr, 0x00, &[]);

        hw.output()
            .set_search_term("[mcu-rom-i3c-svc] PING received");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(
            output_text.contains("[mcu-rom-i3c-svc] Packet seq mismatch"),
            "Sequence mismatch should be logged"
        );
        assert!(
            output_text.contains("[mcu-rom-i3c-svc] PING received"),
            "Handler should recover and process PING after error"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that after a failed DOT command (invalid payload), the handler
    /// continues to accept subsequent commands.
    #[test]
    fn test_i3c_services_dot_error_then_continue() {
        use caliptra_mcu_rom_common::DOT_BLOB_SIZE;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let i3c_port = PortPicker::new().random(true).pick().unwrap();
        let dot_flash = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            dot_flash_initial_contents: Some(dot_flash),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(stream);

        wait_for_i3c_ready(&mut hw);

        // Send DOT_RECOVERY with invalid (too small) payload
        stream.send_packetized_write(target_addr, 0x02, &[0x00, 0x01]);

        hw.output()
            .set_search_term("[mcu-rom-i3c-svc] DOT_RECOVERY payload too small");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 60
        });
        assert!(
            hw.output()
                .take(usize::MAX)
                .contains("DOT_RECOVERY payload too small"),
            "Invalid payload should be rejected"
        );

        // Now send a valid DOT_STATUS — handler should still work
        stream.send_packetized_write(target_addr, 0x01, &[]);

        hw.output()
            .set_search_term("[mcu-rom-i3c-svc] DOT_STATUS received");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 60
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(
            output_text.contains("[mcu-rom-i3c-svc] DOT_STATUS received"),
            "Handler should continue processing after a failed DOT command"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    // ── Test helpers ──────────────────────────────────────────────────

    fn generate_random_ecc_keys() -> ([u8; 48], [u8; 48], [u8; 48]) {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let secret_key = p384::SecretKey::random(&mut rand::thread_rng());
        let pub_point = secret_key.public_key().to_encoded_point(false);
        let x_bytes: [u8; 48] = pub_point.x().unwrap().as_slice().try_into().unwrap();
        let y_bytes: [u8; 48] = pub_point.y().unwrap().as_slice().try_into().unwrap();
        let priv_bytes: [u8; 48] = secret_key.to_bytes().into();
        (x_bytes, y_bytes, priv_bytes)
    }

    fn generate_random_mldsa_keys() -> (Vec<u8>, fips204::ml_dsa_87::PrivateKey) {
        use fips204::ml_dsa_87;
        use fips204::traits::SerDes;
        let (pk, sk) =
            ml_dsa_87::try_keygen_with_rng(&mut rand::thread_rng()).expect("MLDSA keygen failed");
        (pk.into_bytes().to_vec(), sk)
    }

    fn compute_recovery_pk_hash(
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8],
    ) -> [u8; 48] {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(ecc_pub_x);
        hasher.update(ecc_pub_y);
        hasher.update(mldsa_pub);
        let result = hasher.finalize();
        let mut hash = [0u8; 48];
        hash.copy_from_slice(&result);
        hash
    }

    fn create_challenge_recovery_otp_memory(pk_hash: &[u8; 48]) -> Vec<u8> {
        use caliptra_mcu_otp_digest::{otp_scramble, OTP_SCRAMBLE_KEYS};
        use caliptra_mcu_registers_generated::fuses;

        let required_size = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset
            + fuses::VENDOR_RECOVERY_PK_HASH.byte_size
            + 16;
        let otp_size =
            required_size.max(fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size);
        let mut otp = vec![0u8; otp_size];
        otp[fuses::DOT_INITIALIZED.byte_offset] = 0x07;
        otp[fuses::DOT_FUSE_ARRAY.byte_offset] = 0x01;

        // VENDOR_RECOVERY_PK_HASH lives in the vendor_secret_prod_partition
        // (partition 13) which is scrambled with key index 5. Pre-scramble
        // the hash so DAI reads return the correct plaintext.
        let scramble_key = OTP_SCRAMBLE_KEYS[5];
        let hash_offset = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset;
        let mut hash_buf = [0u8; 48];
        hash_buf.copy_from_slice(pk_hash);
        // Scramble in 8-byte chunks
        for chunk in hash_buf.chunks_exact_mut(8) {
            let plaintext = u64::from_le_bytes(chunk.try_into().unwrap());
            let scrambled = otp_scramble(plaintext, scramble_key);
            chunk.copy_from_slice(&scrambled.to_le_bytes());
        }
        otp[hash_offset..hash_offset + 32].copy_from_slice(&hash_buf[..32]);
        let next_offset = hash_offset + fuses::VENDOR_RECOVERY_PK_HASH.byte_size;
        otp[next_offset..next_offset + 16].copy_from_slice(&hash_buf[32..48]);
        otp
    }
}
