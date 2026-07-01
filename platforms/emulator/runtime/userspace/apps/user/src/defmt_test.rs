// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-defmt-logging-mailbox",
    feature = "test-defmt-logging-release",
    feature = "test-defmt-logging-vdm"
))]
pub(crate) fn emit_test_frames() {
    #[cfg(target_arch = "riscv32")]
    {
        defmt::info!("defmt userspace logging round-trip {=u32}", 0x00C0_FFEE_u32);
        defmt::warn!("defmt second frame value={=u16}", 0xBEEF_u16);
        defmt::error!("defmt third frame label={=str}", "caliptra");
        defmt::trace!("defmt trace frame byte={=u8}", 0x2A_u8);
        defmt::debug!("defmt debug frame flag={=bool}", true);
        defmt::info!("defmt signed frame delta={=i32}", -12345_i32);
        defmt::info!("defmt small signed frame s={=i8}", -7_i8);
        defmt::info!("defmt hex frame addr={=u32:08x}", 0xDEAD_BEEF_u32);
        defmt::info!("defmt char frame c={=char}", 'C');
        defmt::info!("defmt multi frame a={=u8} b={=u16}", 1_u8, 513_u16);
        defmt::info!(
            "defmt slice frame data={=[u8]}",
            &[0xDE_u8, 0xAD, 0xBE, 0xEF][..]
        );

        // Oversized: encoded form exceeds STAGE_LEN (256 B); the logger must
        // drop it whole without desyncing the frames after it.
        const OVERSIZED: [u8; 320] = [0xA5; 320];
        defmt::info!("defmt oversized frame data={=[u8]}", &OVERSIZED[..]);

        // Last, so the decoded count proves the oversized frame was dropped once.
        defmt::info!(
            "defmt dropped count={=usize}",
            caliptra_mcu_userlog::dropped()
        );
    }
}
