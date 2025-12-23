// Licensed under the Apache-2.0 license

use crate::cmd_interface::MsgHandlerError;
use libapi_caliptra::crypto::{
    hash::{HashAlgoType, HashContext},
    rng::Rng,
};
use libsyscall_caliptra::{mcu_mbox::MbxCmdStatus, otp, DefaultSyscalls};
use mcu_mbox_common::messages::{CommandId, McuMailboxResp, McuProvisionHek, McuProvisionHekResp};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub struct OcpLock;

impl OcpLock {
    /// Handle external OCP LOCK commands
    ///
    /// # Arguments
    ///
    /// * `msg_buf` - in/out message buffer contains the request as input and response as output
    /// * `cmd` - Command ID
    /// * `req_len` - Request length
    pub async fn command_handler(
        msg_buf: &mut [u8],
        cmd: CommandId,
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        match cmd {
            CommandId::MC_PROVISION_HEK => Self::handle_provision_hek(msg_buf, req_len).await,
            _ => Err(MsgHandlerError::UnsupportedCommand),
        }
    }

    /// Get the total number of HEK slots
    pub fn total_heks() -> Result<u32, MsgHandlerError> {
        let otp = otp::Otp::<DefaultSyscalls>::new();
        otp.read(otp::reg::LOCK_TOTAL_HEKS, 0)
            .map_err(|_| MsgHandlerError::ReadError)
    }

    /// Get the list of valid HEK syscall slot IDs
    fn hek_slots() -> Result<&'static [u32], MsgHandlerError> {
        let total_heks = Self::total_heks()?;
        otp::reg::LOCK_HEK_PROD_ALL
            .get(..total_heks as usize)
            .ok_or(MsgHandlerError::McuMboxCommon)
    }

    /// Get the HEK syscall slot ID of the next unprovisioned HEK
    async fn next_unprovisioned() -> Result<u32, MsgHandlerError> {
        for slot in Self::hek_slots()? {
            let hek_info = HekInfo::from_otp(*slot)?;
            match hek_info.state().await? {
                HekOtpState::Unprovisioned => {
                    return Ok(*slot);
                }
                HekOtpState::Zeroized => (),
                HekOtpState::Provisioned => Err(MsgHandlerError::Busy)?,
                HekOtpState::Corrupted => Err(MsgHandlerError::NotReady)?,
            }
        }
        Err(MsgHandlerError::NoMemory)
    }

    async fn handle_provision_hek(
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req: &McuProvisionHek = McuProvisionHek::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // TODO(#715): add support for authorized commands and verify it here
        if false {
            return Err(MsgHandlerError::PermissionDenied);
        }

        if req.slot >= OcpLock::total_heks()? {
            return Err(MsgHandlerError::InvalidParams);
        }

        // Make sure the requested slot is also the next available
        let slot = OcpLock::next_unprovisioned().await?;
        if slot != req.slot {
            return Err(MsgHandlerError::InvalidParams);
        }

        // Generate a new random HEK seed and write it to OTP
        let hek = HekInfo::from_random().await?;
        hek.write_to_otp(slot)?;

        let mbox_cmd_status = MbxCmdStatus::Complete;
        let mut resp = McuMailboxResp::ProvisionHek(McuProvisionHekResp::default());

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }
}

/// Raw OTP interpretation of an HEK partition
#[repr(C)]
#[derive(Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct HekInfo {
    /// HEK seed to be used in OCP LOCK
    seed: [u8; 32],
    /// Digest of the HEK seed
    digest: OtpDigest,
    /// Whether the slot is zeroized or not
    zero: [u8; 8],
}

impl HekInfo {
    /// Read the HEK information from OTP.
    ///
    /// # Arguments
    ///
    /// * `slot` - Syscall slot identifier
    pub fn from_otp(slot: u32) -> Result<Self, MsgHandlerError> {
        let otp = otp::Otp::<DefaultSyscalls>::new();
        let mut hek_info = HekInfo::default();
        for (index, chunk) in hek_info.as_mut_bytes().chunks_exact_mut(4).enumerate() {
            let word = otp
                .read(slot, index as u32)
                .map_err(|_| MsgHandlerError::ReadError)?;
            // TODO: check endianness
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(hek_info)
    }

    /// Generate a new HEK seed and calculate its digest.
    pub async fn from_random() -> Result<Self, MsgHandlerError> {
        // Make a random seed
        let mut seed = [0u8; 32];
        Rng::generate_random_number(&mut seed)
            .await
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        Ok(Self {
            seed,
            digest: OtpDigest::calculate(&seed).await?,
            zero: [0; 8],
        })
    }

    /// Create a zeroized HEK
    pub fn zeroized() -> Self {
        Self {
            seed: [0xff; 32],
            digest: OtpDigest::zeroized(),
            zero: [0xff; 8],
        }
    }

    /// Get the state of the HEK
    pub async fn state(&self) -> Result<HekOtpState, MsgHandlerError> {
        if self.unprovisioned() {
            Ok(HekOtpState::Unprovisioned)
        } else if self.is_zeroized() {
            Ok(HekOtpState::Zeroized)
        } else if self.provisioned().await? {
            Ok(HekOtpState::Provisioned)
        } else {
            Err(MsgHandlerError::NotReady)
        }
    }

    /// Write the HEK information to OTP.
    ///
    /// # Arguments
    ///
    /// * `slot` - Syscall slot identifier
    pub fn write_to_otp(&self, slot: u32) -> Result<(), MsgHandlerError> {
        let otp = otp::Otp::<DefaultSyscalls>::new();
        for (index, chunk) in self.as_bytes().chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            otp.write(slot, index as u32, word)
                .map_err(|_| MsgHandlerError::WriteError)?;
        }
        Ok(())
    }

    /// Is the HEK unprovisioned
    fn unprovisioned(&self) -> bool {
        self == &Self::default()
    }

    /// Is the HEK provisioned with a valid digest
    async fn provisioned(&self) -> Result<bool, MsgHandlerError> {
        let expected_digest = OtpDigest::calculate(&self.seed).await?;
        Ok(self.digest == expected_digest)
    }

    /// Is the HEK zeroized
    fn is_zeroized(&self) -> bool {
        self == &Self::zeroized()
    }
}

#[repr(C)]
#[derive(Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct OtpDigest([u8; 8]);

impl OtpDigest {
    pub fn zeroized() -> Self {
        Self([0xff; 8])
    }

    pub async fn calculate(data: &[u8]) -> Result<Self, MsgHandlerError> {
        let mut hash_full = [0u8; 48];
        HashContext::hash_all(HashAlgoType::SHA384, data, &mut hash_full)
            .await
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;
        let mut digest = [0; 8];
        digest.copy_from_slice(&hash_full[40..48]);
        Ok(Self(digest))
    }
}

/// The state of an HEK partition
pub enum HekOtpState {
    Unprovisioned,
    Provisioned,
    Zeroized,
    Corrupted,
}
