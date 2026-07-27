// Licensed under the Apache-2.0 license

//! Emulator round-trip test for defmt userspace logging over the MCU mailbox.
//!
//! Boots with `test-defmt-logging-mailbox`, reads the appended frames back via
//! `MC_GET_LOG`, and decodes them against the user-app ELF with `defmt-decoder`.

#[cfg(all(test, not(feature = "fpga_realtime")))]
mod test {
    use crate::test::{compile_runtime, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_mbox_common::messages::{
        GetLogReq, MailboxReqHeader, MailboxRespHeaderVarSize, McuMailboxReq,
    };
    use caliptra_mcu_romtime::McuBootMilestones;
    use std::mem::size_of;
    use std::sync::atomic::Ordering;
    use zerocopy::FromBytes;

    const FEATURE: &str = "test-defmt-logging-mailbox";
    /// Decoded messages the user app emits at startup (see `defmt_test.rs`).
    /// Values: 0x00C0_FFEE -> 12648430, 0xBEEF -> 48879, 0x2A -> 42,
    /// 0xDEAD_BEEF -> "deadbeef" via `{=u32:08x}`, byte slice rendered decimal.
    const EXPECTED_MESSAGES: &[&str] = &[
        "defmt userspace logging round-trip 12648430",
        "defmt second frame value=48879",
        "defmt third frame label=caliptra",
        "defmt trace frame byte=42",
        "defmt debug frame flag=true",
        "defmt signed frame delta=-12345",
        "defmt small signed frame s=-7",
        "defmt hex frame addr=deadbeef",
        "defmt char frame c=C",
        "defmt multi frame a=1 b=513",
        "defmt slice frame data=[222, 173, 190, 239]",
        // The oversized frame (320-byte slice) is dropped by the logger, so the
        // only drop seen here is that one frame.
        "defmt dropped count=1",
    ];

    const DROPPED_FRAME_MARKER: &str = "oversized";
    const MAILBOX_TIMEOUT_CYCLES: u64 = 20_000_000;

    /// Execute a mailbox command with a large timeout and return the raw
    /// response bytes. Mirrors the helper used by the mailbox validator test.
    fn mailbox_execute_with_timeout(
        hw: &mut impl McuHwModel,
        cmd: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        hw.start_mailbox_execute(cmd, payload)
            .map_err(|e| format!("start_mailbox_execute failed: {}", e))?;

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

    /// Read the user-app ELF that the device booted with. The `.defmt` section
    /// holds the interned format strings the decoder needs.
    ///
    /// Tries the firmware bundle first (works on CI where the host has no
    /// access to the build tree because firmware is prebuilt by a separate
    /// job and shipped as artifacts), then falls back to the build's on-disk
    /// path (typical local emulator runs that build firmware on demand).
    fn user_app_elf() -> Vec<u8> {
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            if let Some(bytes) = binaries
                .as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_DEFMT_LOGGING_MAILBOX)
                .mcu_fw
                .user_app_elf
                .as_deref()
            {
                return bytes.to_vec();
            }
        }

        let path = caliptra_mcu_builder::target_dir()
            .join(caliptra_mcu_builder::TARGET)
            .join("devel")
            .join("user-app");
        if !path.exists() {
            let _ = compile_runtime(Some(FEATURE), false);
        }
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read user-app ELF {}: {}", path.display(), e))
    }

    #[test]
    fn test_defmt_logging_mailbox() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_DEFMT_LOGGING_MAILBOX,
            ..Default::default()
        });

        // Wait for the firmware mailbox to be ready.
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        // Build the GetLog request for the debug log (log_type 0).
        let mut req = McuMailboxReq::GetLog(GetLogReq {
            hdr: MailboxReqHeader::default(),
            log_type: 0,
        });
        req.populate_chksum().expect("populate_chksum");
        let cmd = req.cmd_code().0;
        let payload = req.as_bytes().expect("as_bytes").to_vec();

        // Retry until the appended frame is drained from flash. Issuing the
        // command steps the emulator, which also lets the drain task run.
        let mut log_bytes: Vec<u8> = Vec::new();
        const HDR_LEN: usize = size_of::<MailboxRespHeaderVarSize>();
        const MORE_DATA_LEN: usize = size_of::<u32>();
        for _ in 0..32 {
            let resp = mailbox_execute_with_timeout(&mut hw, cmd, &payload)
                .expect("GetLog mailbox command failed")
                .unwrap_or_default();

            if resp.len() >= HDR_LEN + MORE_DATA_LEN {
                let hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp[..HDR_LEN])
                    .expect("parse response header");
                let data_len = hdr.data_len as usize;
                let data = &resp[HDR_LEN..HDR_LEN + data_len];
                let more_data = u32::from_le_bytes(data[..MORE_DATA_LEN].try_into().unwrap());
                let frame_bytes = &data[MORE_DATA_LEN..];
                if !frame_bytes.is_empty() {
                    log_bytes.extend_from_slice(frame_bytes);
                    if more_data == 0 {
                        break;
                    }
                    continue;
                }
            }

            // No data yet; step the emulator a little and retry.
            for _ in 0..50_000 {
                hw.step();
            }
        }

        assert!(
            !log_bytes.is_empty(),
            "GetLog returned no defmt frame bytes"
        );
        // Decode the rzCOBS stream against the user-app ELF.
        let elf = user_app_elf();
        let table = defmt_decoder::Table::parse(&elf)
            .expect("failed to parse .defmt table")
            .expect("user-app ELF has no .defmt section");
        let mut decoder = table.new_stream_decoder();
        decoder.received(&log_bytes);

        let mut messages: Vec<String> = Vec::new();
        loop {
            match decoder.decode() {
                Ok(frame) => messages.push(frame.display_message().to_string()),
                Err(defmt_decoder::DecodeError::UnexpectedEof) => break,
                Err(e) => panic!(
                    "defmt decode error: {:?}; decoded so far: {:?}",
                    e, messages
                ),
            }
        }

        for expected in EXPECTED_MESSAGES {
            assert!(
                messages.iter().any(|m| m == expected),
                "expected defmt message {:?} not found; decoded: {:?}",
                expected,
                messages
            );
        }

        // Negative case: the oversized frame must have been dropped by the
        // logger, so its text must never appear in the decoded stream. Every
        // EXPECTED_MESSAGES frame above still decoded, which proves the drop did
        // not desync the frames emitted after it.
        assert!(
            !messages.iter().any(|m| m.contains(DROPPED_FRAME_MARKER)),
            "oversized frame should have been dropped but was decoded: {:?}",
            messages
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
