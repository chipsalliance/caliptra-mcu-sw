/*++

Licensed under the Apache-2.0 license.

File Name:

    dot_override.rs

Abstract:

    DOT override challenge/response transport using MCI mbox0.

    This module implements the `RecoveryTransport` trait using MCI mailbox 0
    to communicate with the BMC for DOT override operations.
    The BMC provides its VendorKey public keys (ECC P-384 + MLDSA-87) and signs
    a challenge with both VendorKey.priv keys.

    See docs/src/dot.md for full protocol documentation.

--*/

use mcu_error::{McuError, McuResult};

use crate::{
    EccP384PublicKey, RecoveryTransport, MLDSA87_PUB_KEY_SIZE_DWORDS, MLDSA87_SIGNATURE_SIZE_DWORDS,
};
use registers_generated::mci;
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub const CMD_DOT_UNLOCK_CHALLENGE: u32 = 0x444F_5457;
pub const CMD_DOT_OVERRIDE: u32 = 0x444F_5458;

/// Challenge type field values for DOT_UNLOCK_CHALLENGE.
pub const CHALLENGE_TYPE_UNLOCK: u32 = 0x01;
pub const CHALLENGE_TYPE_OVERRIDE: u32 = 0x02;

#[repr(C)]
struct OverrideChallengeRequest {
    chksum: u32,
    challenge_type: u32,
    ecc_pub_key_x: [u32; 12],
    ecc_pub_key_y: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
}

#[repr(C)]
struct OverrideResponse {
    chksum: u32,
    ecc_pub_key_x: [u32; 12],
    ecc_pub_key_y: [u32; 12],
    ecc_sig_r: [u32; 12],
    ecc_sig_s: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    mldsa_signature: [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
}

/// MCI mbox0 helpers for the override transport.
#[derive(Clone, Copy)]
struct Mbox0Helpers {
    mci: StaticRef<mci::regs::Mci>,
}

impl Mbox0Helpers {
    fn new(mci: StaticRef<mci::regs::Mci>) -> Self {
        mci.intr_block_rf_notif0_intr_en_r
            .modify(mci::bits::Notif0IntrEnT::NotifMbox0CmdAvailEn::SET);
        Self { mci }
    }

    /// # Safety
    /// Caller must ensure the SRAM contains a valid `T` at offset 0.
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

    fn cmd_failure(&self) {
        self.mci
            .mcu_mbox0_csr_mbox_cmd_status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
    }

    fn dlen(&self) -> usize {
        self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize
    }
}

/// DOT recovery transport using MCI mbox0.
pub struct Mbox0RecoveryTransport {
    helpers: Mbox0Helpers,
}

impl Mbox0RecoveryTransport {
    pub fn new(mci: StaticRef<mci::regs::Mci>) -> Self {
        Self {
            helpers: Mbox0Helpers::new(mci),
        }
    }
}

impl RecoveryTransport for Mbox0RecoveryTransport {
    fn wait_for_override_request(&self) -> McuResult<crate::OverrideRequest<'_>> {
        let cmd = self.helpers.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_UNLOCK_CHALLENGE {
            romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_UNLOCK_CHALLENGE",
                cmd
            );
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = self.helpers.dlen();
        if dlen < core::mem::size_of::<OverrideChallengeRequest>() {
            romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE dlen too small");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !self.helpers.verify_checksum(cmd, dlen) {
            romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE checksum failed");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let req = unsafe { self.helpers.sram_as::<OverrideChallengeRequest>() };

        if req.challenge_type != CHALLENGE_TYPE_OVERRIDE {
            romtime::println!(
                "[dot-override] Unsupported challenge_type: {:#x}, expected OVERRIDE ({:#x})",
                req.challenge_type,
                CHALLENGE_TYPE_OVERRIDE
            );
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let ecc_pub_key = EccP384PublicKey {
            x: req.ecc_pub_key_x,
            y: req.ecc_pub_key_y,
        };
        let mldsa_pub_key = &req.mldsa_pub_key;

        romtime::println!("[dot-override] Override challenge request received via mbox0");

        Ok(crate::OverrideRequest {
            ecc_pub_key,
            mldsa_pub_key,
        })
    }

    fn send_challenge(&self, challenge: &[u8; 48]) -> McuResult<()> {
        romtime::println!("[dot-override] Sending challenge via mbox0");
        self.helpers.send_mbox0_response(challenge);
        Ok(())
    }

    fn receive_override_response(&self) -> McuResult<crate::OverrideChallengeResponse<'_>> {
        let cmd = self.helpers.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_OVERRIDE {
            romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_OVERRIDE",
                cmd
            );
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = self.helpers.dlen();
        if dlen < core::mem::size_of::<OverrideResponse>() {
            romtime::println!("[dot-override] DOT_OVERRIDE dlen too small");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !self.helpers.verify_checksum(cmd, dlen) {
            romtime::println!("[dot-override] DOT_OVERRIDE checksum failed");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let resp = unsafe { self.helpers.sram_as::<OverrideResponse>() };
        let ecc_pub_key = EccP384PublicKey {
            x: resp.ecc_pub_key_x,
            y: resp.ecc_pub_key_y,
        };
        let ecc_signature_r = Mbox0Helpers::u32x12_to_bytes(&resp.ecc_sig_r);
        let ecc_signature_s = Mbox0Helpers::u32x12_to_bytes(&resp.ecc_sig_s);
        let mldsa_pub_key = &resp.mldsa_pub_key;
        let mldsa_signature = &resp.mldsa_signature;

        romtime::println!("[dot-override] Override response received via mbox0");

        Ok(crate::OverrideChallengeResponse {
            ecc_pub_key,
            ecc_signature_r,
            ecc_signature_s,
            mldsa_signature,
            mldsa_pub_key,
        })
    }
}
