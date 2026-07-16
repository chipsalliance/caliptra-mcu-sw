// Licensed under the Apache-2.0 license

use crate::auth_keys::{TEST_AUTH_ECC_PUB_KEY_X, TEST_AUTH_ECC_PUB_KEY_Y, TEST_AUTH_MLDSA_PUB_KEY};
use caliptra_mcu_common_commands::{AuthorizationError, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq,
    HybridSignature, MailboxReqHeader, McuFeProgReq, ProvisionVendorPkHashReq,
};
use core::cell::RefCell;
use core::mem::size_of;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use mcu_caliptra_api_lite::ApiAlloc;
use zerocopy::FromBytes;

extern crate alloc;

static CHALLENGE: Mutex<CriticalSectionRawMutex, RefCell<Option<[u8; 32]>>> =
    Mutex::new(RefCell::new(None));

#[derive(Default)]
pub struct MockCommandAuthorizer;

fn set_challenge(challenge: [u8; 32]) {
    CHALLENGE.lock(|state| *state.borrow_mut() = Some(challenge));
}

impl CommandAuthorizer for MockCommandAuthorizer {
    async fn is_authorized<'a, Alloc: ApiAlloc>(
        &mut self,
        _alloc: &Alloc,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> Result<&'a [u8], AuthorizationError> {
        let cmd_len = match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => size_of::<ProvisionVendorPkHashReq>(),
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                size_of::<FuseIncreaseCaliptraMinSvnReq>()
            }
            CommandId::MC_FE_PROG => size_of::<McuFeProgReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => size_of::<FuseRevokeVendorPubKeyReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => size_of::<FuseRevokeVendorPkHashReq>(),
            _ => return Err(AuthorizationError),
        };

        let sigs_bytes = req
            .get(cmd_len..cmd_len + size_of::<HybridSignature>())
            .ok_or(AuthorizationError)?;
        let sig = HybridSignature::ref_from_bytes(sigs_bytes).map_err(|_| AuthorizationError)?;
        let cmd_body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or(AuthorizationError)?;

        self.verify_signatures(u32::from(cmd_id), cmd_body, sig)
            .await?;
        Ok(&req[..cmd_len])
    }

    async fn verify_signatures(
        &mut self,
        cmd_id: u32,
        payload: &[u8],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError> {
        let challenge = CHALLENGE
            .lock(|state| state.borrow_mut().take())
            .ok_or(AuthorizationError)?;

        crate::caliptra_cmd_handler::device_ops::verify_authorized_signatures(
            cmd_id,
            payload,
            &challenge,
            TEST_AUTH_ECC_PUB_KEY_X,
            TEST_AUTH_ECC_PUB_KEY_Y,
            TEST_AUTH_MLDSA_PUB_KEY,
            sig,
        )
        .await
        .map_err(|_| AuthorizationError)
    }

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        CHALLENGE.lock(|state| state.borrow_mut().take())
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        set_challenge(challenge);
    }
}
