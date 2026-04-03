/*++

Licensed under the Apache-2.0 license.

File Name:

    dot_recovery.rs

Abstract:

    DOT challenge/response recovery transport using MCI mbox0.

    This module implements the `RecoveryTransport` trait using MCI mailbox 0
    to communicate with an external agent (e.g., BMC) for DOT recovery.
    The external agent performs ECDSA P-384 and MLDSA-87 signing since
    the Caliptra ROM does not support CM_IMPORT or CM_SIGN commands.

    See docs/src/dot.md for full protocol documentation.

--*/

use mcu_error::{McuError, McuResult};

use crate::{
    DotBlobData, EccP384PublicKey, LakPkHash, OwnerPkHash, RecoveryTransport,
    MLDSA87_PUB_KEY_SIZE_DWORDS, MLDSA87_SIGNATURE_SIZE_DWORDS,
};
use registers_generated::mci;
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub const CMD_DOT_RECOVERY_REQUEST: u32 = 0x444F_5451;
pub const CMD_DOT_CHALLENGE_RESPONSE: u32 = 0x444F_5452;

#[repr(C)]
struct RecoveryRequest {
    chksum: u32,
    ecc_pub_key_x: [u32; 12],
    ecc_pub_key_y: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    cak: [u32; 12],
    lak: [u32; 12],
}

#[repr(C)]
struct ChallengeResponse {
    chksum: u32,
    ecc_sig_r: [u32; 12],
    ecc_sig_s: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    mldsa_signature: [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
}

/// DOT recovery transport using MCI mbox0.
pub struct Mbox0RecoveryTransport {
    mci: StaticRef<mci::regs::Mci>,
}

impl Mbox0RecoveryTransport {
    pub fn new(mci: StaticRef<mci::regs::Mci>) -> Self {
        mci.intr_block_rf_notif0_intr_en_r
            .modify(mci::bits::Notif0IntrEnT::NotifMbox0CmdAvailEn::SET);
        Self { mci }
    }

    unsafe fn sram_as<T>(&self) -> &T {
        &*(self.mci.mcu_mbox0_csr_mbox_sram.as_ptr() as *const T)
    }

    /// Convert a `[u32; 12]` to `[u8; 48]` recovering the host byte order.
    fn u32x12_to_bytes(words: &[u32; 12]) -> [u8; 48] {
        let mut out = [0u8; 48];
        for i in 0..12 {
            let bytes = words[i].to_le_bytes();
            for j in 0..4 {
                out[i * 4 + j] = bytes[j];
            }
        }
        out
    }

    fn verify_checksum(&self, cmd: u32, dlen: usize) -> bool {
        let sram = &self.mci.mcu_mbox0_csr_mbox_sram;
        let sram = unsafe { core::slice::from_raw_parts(sram.as_ptr() as *const u32, sram.len()) };
        let stored_checksum = match sram.first() {
            Some(&v) => v,
            None => return false,
        };

        let mut sum = 0u32;
        for b in cmd.to_le_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let payload_len = if dlen > 4 { dlen - 4 } else { 0 };
        let payload_words = payload_len.div_ceil(4).min(sram.len().saturating_sub(1));
        for i in 0..payload_words {
            if let Some(&word) = sram.get(i + 1) {
                for b in word.to_le_bytes() {
                    sum = sum.wrapping_add(b as u32);
                }
            }
        }

        stored_checksum == 0u32.wrapping_sub(sum)
    }

    fn wait_for_mbox0_cmd(&self) -> u32 {
        let notif0 = &self.mci.intr_block_rf_notif0_internal_intr_r;
        while notif0.read(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts) == 0 {}
        notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
        self.mci.mcu_mbox0_csr_mbox_cmd.get()
    }

    fn send_mbox0_response(&self, data: &[u8]) {
        let sram = &self.mci.mcu_mbox0_csr_mbox_sram;
        let sram =
            unsafe { core::slice::from_raw_parts_mut(sram.as_ptr() as *mut u32, sram.len()) };
        let len_words = data.len().div_ceil(4).min(sram.len());
        for i in 0..len_words {
            let byte_off = i * 4;
            let mut word_bytes = [0u8; 4];
            for (j, wb) in word_bytes.iter_mut().enumerate() {
                if let Some(&b) = data.get(byte_off + j) {
                    *wb = b;
                }
            }
            if let Some(w) = sram.get_mut(i) {
                *w = u32::from_le_bytes(word_bytes);
            }
        }
        self.mci.mcu_mbox0_csr_mbox_dlen.set(data.len() as u32);
        self.mci
            .mcu_mbox0_csr_mbox_cmd_status
            .write(mci::bits::MboxCmdStatus::Status::DataReady);
    }
}

impl RecoveryTransport for Mbox0RecoveryTransport {
    fn wait_for_recovery_request(&self) -> McuResult<crate::RecoveryRequest<'_>> {
        let cmd = self.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_RECOVERY_REQUEST {
            romtime::println!(
                "[dot-recovery] Unexpected mbox0 cmd: {:#x}, expected DOT_RECOVERY_REQUEST",
                cmd
            );
            self.mci
                .mcu_mbox0_csr_mbox_cmd_status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return Err(McuError::ROM_DOT_RECOVERY_CHALLENGE_FAILED);
        }

        let dlen = self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize;
        if !self.verify_checksum(cmd, dlen) {
            romtime::println!("[dot-recovery] DOT_RECOVERY_REQUEST checksum failed");
            self.mci
                .mcu_mbox0_csr_mbox_cmd_status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return Err(McuError::ROM_DOT_RECOVERY_CHALLENGE_FAILED);
        }

        let req = unsafe { self.sram_as::<RecoveryRequest>() };
        let ecc_pub_key = EccP384PublicKey {
            x: req.ecc_pub_key_x,
            y: req.ecc_pub_key_y,
        };
        let mldsa_pub_key = &req.mldsa_pub_key;
        let cak = OwnerPkHash(req.cak);
        let lak = LakPkHash(req.lak);

        romtime::println!("[dot-recovery] Recovery request received via mbox0");

        Ok(crate::RecoveryRequest {
            ecc_pub_key,
            mldsa_pub_key,
            new_dot_blob_data: DotBlobData { cak, lak },
        })
    }

    fn send_challenge(&self, challenge: &[u8; 48]) -> McuResult<()> {
        romtime::println!("[dot-recovery] Sending challenge via mbox0");
        self.send_mbox0_response(challenge);
        Ok(())
    }

    fn receive_challenge_response(&self) -> McuResult<crate::ChallengeResponse<'_>> {
        let cmd = self.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_CHALLENGE_RESPONSE {
            romtime::println!(
                "[dot-recovery] Unexpected mbox0 cmd: {:#x}, expected DOT_CHALLENGE_RESPONSE",
                cmd
            );
            self.mci
                .mcu_mbox0_csr_mbox_cmd_status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return Err(McuError::ROM_DOT_RECOVERY_CHALLENGE_FAILED);
        }

        let dlen = self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize;
        if !self.verify_checksum(cmd, dlen) {
            romtime::println!("[dot-recovery] DOT_CHALLENGE_RESPONSE checksum failed");
            self.mci
                .mcu_mbox0_csr_mbox_cmd_status
                .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            return Err(McuError::ROM_DOT_RECOVERY_CHALLENGE_FAILED);
        }

        let resp = unsafe { self.sram_as::<ChallengeResponse>() };
        let ecc_signature_r = Self::u32x12_to_bytes(&resp.ecc_sig_r);
        let ecc_signature_s = Self::u32x12_to_bytes(&resp.ecc_sig_s);
        let mldsa_pub_key = &resp.mldsa_pub_key;
        let mldsa_signature = &resp.mldsa_signature;

        romtime::println!("[dot-recovery] Challenge response received via mbox0");

        Ok(crate::ChallengeResponse {
            ecc_signature_r,
            ecc_signature_s,
            mldsa_signature,
            mldsa_pub_key,
        })
    }
}
