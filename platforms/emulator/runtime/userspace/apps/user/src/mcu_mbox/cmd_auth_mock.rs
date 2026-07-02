// Licensed under the Apache-2.0 license
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    EcdsaVerifyReq, MailboxReqHeader as CaliptraMailboxReqHeader,
    MailboxRespHeader as CaliptraMailboxRespHeader, MldsaVerifyReq,
};
use caliptra_mcu_common_commands::{AuthorizationError, AuthorizationResult, CommandAuthorizer};
use caliptra_mcu_libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq,
    HybridSignature, MailboxReqHeader, McuFeProgReq, OcpLockRotateHekReq, ProvisionVendorPkHashReq,
};
use core::mem::size_of;
use keys::{TEST_AUTH_ECC_PUB_KEY_X, TEST_AUTH_ECC_PUB_KEY_Y, TEST_AUTH_MLDSA_PUB_KEY};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod keys;

#[derive(Default)]
pub struct MockCommandAuthorizer {
    challenge: Option<[u8; 32]>,
}

#[async_trait]
impl CommandAuthorizer for MockCommandAuthorizer {
    async fn is_authorized<'a>(
        &mut self,
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
            CommandId::MC_OCP_LOCK_ROTATE_HEK => size_of::<OcpLockRotateHekReq>(),
            _ => Err(AuthorizationError)?,
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

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        self.challenge.take()
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        self.challenge = Some(challenge)
    }
}

impl MockCommandAuthorizer {
    async fn verify_signatures(
        &mut self,
        cmd_id: u32,
        payload: &[u8],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError> {
        let challenge = self.challenge.take().ok_or(AuthorizationError)?;

        // Reconstruct the message that was signed: cmd_id(BE,4) + payload + challenge(32)
        let mut message = arrayvec::ArrayVec::<u8, 256>::new();
        message.extend(cmd_id.to_be_bytes());
        message.extend(payload.iter().copied());
        message.extend(challenge.iter().copied());

        let mailbox = Mailbox::new();

        // 1. Verify ECC P-384 Signature using Caliptra Mailbox
        // Compute SHA-384 hash of the message using Caliptra Mailbox
        let mut hash = [0u8; 48];
        HashContext::hash_all(HashAlgoType::SHA384, message.as_slice(), &mut hash)
            .await
            .map_err(|_| AuthorizationError)?;

        let mut ecc_req = EcdsaVerifyReq {
            hdr: CaliptraMailboxReqHeader::default(),
            pub_key_x: TEST_AUTH_ECC_PUB_KEY_X,
            pub_key_y: TEST_AUTH_ECC_PUB_KEY_Y,
            signature_r: sig.ecc_sig_r,
            signature_s: sig.ecc_sig_s,
            hash,
        };

        let mut ecc_resp = CaliptraMailboxRespHeader::default();

        let ecc_req_bytes = ecc_req.as_mut_bytes();
        let ecc_resp_bytes = ecc_resp.as_mut_bytes();

        let cmd_ecdsa_verify: u32 =
            caliptra_api::mailbox::CommandId::ECDSA384_SIGNATURE_VERIFY.into();

        execute_mailbox_cmd(&mailbox, cmd_ecdsa_verify, ecc_req_bytes, ecc_resp_bytes)
            .await
            .map_err(|_| AuthorizationError)?;

        // 2. Verify ML-DSA-87 Signature using Caliptra Mailbox
        let mut mldsa_req = MldsaVerifyReq {
            hdr: CaliptraMailboxReqHeader::default(),
            pub_key: TEST_AUTH_MLDSA_PUB_KEY,
            signature: sig.mldsa_sig,
            message_size: message.len() as u32,
            message: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
        };
        mldsa_req.message[..message.len()].copy_from_slice(message.as_slice());

        let mut mldsa_resp = CaliptraMailboxRespHeader::default();

        // Use partial serialization to avoid sending 4KB of zeroes
        let mldsa_req_bytes = mldsa_req
            .as_bytes_partial_mut()
            .map_err(|_| AuthorizationError)?;
        let mldsa_resp_bytes = mldsa_resp.as_mut_bytes();

        let cmd_mldsa_verify: u32 =
            caliptra_api::mailbox::CommandId::MLDSA87_SIGNATURE_VERIFY.into();

        execute_mailbox_cmd(
            &mailbox,
            cmd_mldsa_verify,
            mldsa_req_bytes,
            mldsa_resp_bytes,
        )
        .await
        .map_err(|_| AuthorizationError)?;

        Ok(())
    }
}
