// Licensed under the Apache-2.0 license

//! Emulator round-trip test for defmt userspace logging.
//!
//! Boots with `test-defmt-logging`, reads the appended frames back via
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

    const FEATURE: &str = "test-defmt-logging";
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

    /// Read the user-app ELF emitted by the runtime build. The `.defmt` section
    /// holds the interned format strings the decoder needs. The ELF is located
    /// next to the runtime binary produced by the build so the path stays
    /// consistent with the firmware bundler's target directory, which can differ
    /// from `caliptra_mcu_builder::target_dir()` when tests boot from a prebuilt
    /// bundle (e.g. in CI). `compile_runtime` is a no-op when already built.
    fn user_app_elf() -> Vec<u8> {
        let runtime_bin = compile_runtime(Some(FEATURE), false);
        let path = runtime_bin
            .parent()
            .expect("runtime binary path has no parent")
            .join("user-app");
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read user-app ELF {}: {}", path.display(), e))
    }

    #[test]
    fn test_defmt_logging() {
        let lock = TEST_LOCK.lock().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(FEATURE),
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
