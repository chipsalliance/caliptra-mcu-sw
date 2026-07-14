// Licensed under the Apache-2.0 license
use caliptra_mcu_common_commands::{AuthorizationError, AuthorizationResult, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq,
    MailboxReqHeader, McuFeProgReq, ProvisionVendorPkHashReq,
};
use core::mem::size_of;
use mcu_caliptra_api_lite::ApiAlloc;

#[derive(Default)]
pub struct MockCommandAuthorizer {
    challenge: Option<[u8; 32]>,
}

impl CommandAuthorizer for MockCommandAuthorizer {
    async fn is_authorized<'a, Alloc: ApiAlloc>(
        &mut self,
        alloc: &Alloc,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> AuthorizationResult<&'a [u8]> {
        let cmd_len = match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => size_of::<ProvisionVendorPkHashReq>(),
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                size_of::<FuseIncreaseCaliptraMinSvnReq>()
            }
            CommandId::MC_FE_PROG => size_of::<McuFeProgReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => size_of::<FuseRevokeVendorPubKeyReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => size_of::<FuseRevokeVendorPkHashReq>(),
            _ => Err(AuthorizationError)?,
        };

        let received_mac = req.get(cmd_len..cmd_len + 48).ok_or(AuthorizationError)?;

        let cmd_body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or(AuthorizationError)?;

        self.verify_mac(alloc, u32::from(cmd_id), cmd_body, received_mac)
            .await?;

        Ok(&req[..cmd_len])
    }

    async fn verify_mac<Alloc: ApiAlloc>(
        &mut self,
        alloc: &Alloc,
        cmd_id: u32,
        payload: &[u8],
        mac: &[u8],
    ) -> Result<(), AuthorizationError> {
        let challenge = self.challenge.take().ok_or(AuthorizationError)?;
        let mac: &[u8; 48] = mac.try_into().map_err(|_| AuthorizationError)?;
        crate::caliptra_cmd_handler::device_ops::verify_authorized_mac(
            alloc,
            &crate::caliptra_cmd_handler::device_ops::TEST_AUTH_CMD_HMAC_KEY,
            cmd_id,
            payload,
            &challenge,
            mac,
        )
        .await
        .map_err(|_| AuthorizationError)?;
        Ok(())
    }

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        self.challenge.take()
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        self.challenge = Some(challenge)
    }
}
