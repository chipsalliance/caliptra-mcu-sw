// Licensed under the Apache-2.0 license
use async_trait::async_trait;
use caliptra_mcu_common_commands::{AuthorizationError, AuthorizationResult, CommandAuthorizer};
use caliptra_mcu_libapi_caliptra::crypto::hmac::Hmac;
use caliptra_mcu_libapi_caliptra::crypto::import::{CmKeyUsage, Import};
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseRevokeVendorPubKeyReq, MailboxReqHeader,
    McuFeProgReq,
};
use constant_time_eq::constant_time_eq;
use core::mem::size_of;
use zerocopy::IntoBytes;
extern crate alloc;
use alloc::boxed::Box;

/// NOTE: because this is a symmetric secret, this should come from a provisioned secret from OTP
/// instead of embedded into firmware. To keep the implementation generic, this does not add OTP
/// syscalls to get this value, in case a platform chooses another verification method like
/// asymmetric key verification.
const TEST_AUTH_CMD_HMAC_KEY: [u8; 48] = [
    0x72, 0xec, 0x12, 0x02, 0x77, 0x69, 0xb9, 0xdc, 0x04, 0xbd, 0xd0, 0xc0, 0x86, 0xca, 0x1b, 0x20,
    0x2f, 0x47, 0x1e, 0xee, 0xf2, 0x8c, 0x2d, 0xa8, 0xc5, 0x4c, 0x75, 0xc2, 0x48, 0xa6, 0x80, 0x0a,
    0x11, 0xbf, 0xd5, 0xcd, 0x09, 0xed, 0x57, 0x0c, 0xb4, 0xc2, 0xa1, 0x37, 0x6b, 0xa2, 0xcb, 0xcd,
];

#[derive(Default)]
pub struct MockCommandAuthorizer {
    challenge: Option<[u8; 32]>,
}

#[async_trait(?Send)]
impl CommandAuthorizer for MockCommandAuthorizer {
    async fn is_authorized<'a>(
        &mut self,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> AuthorizationResult<&'a [u8]> {
        let cmd_len = match cmd_id {
            CommandId::MC_ROTATE_VENDOR_PK_HASH => Err(AuthorizationError)?,
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                size_of::<FuseIncreaseCaliptraMinSvnReq>()
            }
            CommandId::MC_FE_PROG => size_of::<McuFeProgReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => size_of::<FuseRevokeVendorPubKeyReq>(),
            _ => Err(AuthorizationError)?,
        };

        let challenge = self.challenge.take().ok_or_else(|| AuthorizationError)?;

        let received_mac = req
            .get(cmd_len..cmd_len + 48)
            .ok_or_else(|| AuthorizationError)?;

        // Import the key using Caliptra API
        let import_resp = Import::import(CmKeyUsage::Hmac, &TEST_AUTH_CMD_HMAC_KEY)
            .await
            .map_err(|_| AuthorizationError)?;
        let cmk = import_resp.cmk;

        // Reconstruct the buffer to hash: cmd_id + cmd_body + challenge
        let mut buf = arrayvec::ArrayVec::<u8, 256>::new();
        let cmd_id_bytes = u32::from(cmd_id).to_be_bytes();
        let cmd_body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or_else(|| AuthorizationError)?;

        buf.extend(cmd_id_bytes);
        buf.extend(cmd_body.iter().copied());
        buf.extend(challenge.iter().copied());

        // Compute HMAC using Caliptra API
        let hmac_resp = Hmac::hmac(&cmk, buf.as_slice())
            .await
            .map_err(|_| AuthorizationError)?;

        let computed_mac_all = hmac_resp.mac.as_bytes();
        let computed_mac = &computed_mac_all[..48];

        if !constant_time_eq(computed_mac, received_mac) {
            Err(AuthorizationError)?;
        }
        Ok(&req[..cmd_len])
    }

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        self.challenge.take()
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        self.challenge = Some(challenge)
    }
}
