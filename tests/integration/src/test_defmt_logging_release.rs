// Licensed under the Apache-2.0 license

//! Release-profile round-trip test for userspace defmt logging.

#[cfg(all(test, not(feature = "fpga_realtime")))]
mod test {
    use crate::test::{
        compile_runtime_with_profile, start_runtime_hw_model, TestParams, TEST_LOCK,
    };
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_mbox_common::messages::{
        GetLogReq, MailboxReqHeader, MailboxRespHeaderVarSize, McuMailboxReq,
    };
    use caliptra_mcu_romtime::McuBootMilestones;
    use std::mem::size_of;
    use std::sync::atomic::Ordering;
    use zerocopy::FromBytes;

    const FEATURE: &str = "test-defmt-logging-release";
    const EXPECTED_MESSAGES: &[&str] = &[
        "defmt userspace logging round-trip 12648430",
        "defmt second frame value=48879",
        "defmt third frame label=caliptra",
        "defmt signed frame delta=-12345",
        "defmt small signed frame s=-7",
        "defmt hex frame addr=deadbeef",
        "defmt char frame c=C",
        "defmt multi frame a=1 b=513",
        "defmt slice frame data=[222, 173, 190, 239]",
        "defmt dropped count=1",
    ];
    const FILTERED_MESSAGES: &[&str] = &[
        "defmt trace frame byte=42",
        "defmt debug frame flag=true",
        "oversized",
    ];
    const MAILBOX_TIMEOUT_CYCLES: u64 = 20_000_000;

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

    fn release_runtime_and_user_app_elf() -> (Vec<u8>, Vec<u8>) {
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            let runtime = binaries
                .test_runtime(FEATURE)
                .expect("release firmware bundle has no test-defmt-logging-release runtime");
            let elf = binaries
                .test_user_app_elf(FEATURE)
                .expect("release firmware bundle has no test-defmt-logging-release user-app ELF")
                .to_vec();
            return (runtime, elf);
        }

        let runtime = compile_runtime_with_profile(Some(FEATURE), false, Some("release"));
        let path = caliptra_mcu_builder::target_dir()
            .join(caliptra_mcu_builder::TARGET)
            .join("release")
            .join("user-app");
        let elf = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read user-app ELF {}: {}", path.display(), e));
        let runtime = std::fs::read(&runtime).expect("failed to read release runtime");
        (runtime, elf)
    }

    #[test]
    fn test_defmt_logging_release() {
        let lock = TEST_LOCK.lock().unwrap();
        let (runtime, elf) = release_runtime_and_user_app_elf();

        let mut hw = start_runtime_hw_model(TestParams {
            profile: Some("release"),
            custom_mcu_runtime: Some(runtime),
            ..Default::default()
        });

        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let mut req = McuMailboxReq::GetLog(GetLogReq {
            hdr: MailboxReqHeader::default(),
        });
        req.populate_chksum().expect("populate_chksum");
        let cmd = req.cmd_code().0;
        let payload = req.as_bytes().expect("as_bytes").to_vec();

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

            for _ in 0..50_000 {
                hw.step();
            }
        }

        assert!(
            !log_bytes.is_empty(),
            "GetLog returned no defmt frame bytes"
        );

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
                "expected release defmt message {:?} not found; decoded: {:?}",
                expected,
                messages
            );
        }

        for filtered in FILTERED_MESSAGES {
            assert!(
                !messages.iter().any(|m| m.contains(filtered)),
                "release-only filtered message {:?} was decoded: {:?}",
                filtered,
                messages
            );
        }

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
