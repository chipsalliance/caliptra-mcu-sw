// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{AuthorizationError, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReq, FuseLockPartitionReq, FuseReadReq,
    FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq, FuseWriteReq, HybridSignature,
    MailboxReqHeader, McuFeProgReq, ProvisionVendorPkHashReq, AUTH_CMD_NONCE_LEN,
};
use core::cell::RefCell;
use core::mem::size_of;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use mcu_caliptra_api_lite::ApiAlloc;
use zerocopy::FromBytes;

extern crate alloc;

/// Length of one P-384 public-key coordinate.
const ECC_P384_COORD_LEN: usize = 48;
/// Length of the ML-DSA-87 public key.
const MLDSA87_PUB_KEY_LEN: usize = 2592;

static CHALLENGE: Mutex<CriticalSectionRawMutex, RefCell<Option<[u8; AUTH_CMD_NONCE_LEN]>>> =
    Mutex::new(RefCell::new(None));

#[derive(Default)]
pub struct MockCommandAuthorizer;

fn set_challenge(challenge: [u8; AUTH_CMD_NONCE_LEN]) {
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
            CommandId::MC_FUSE_READ => size_of::<FuseReadReq>(),
            CommandId::MC_FUSE_WRITE => size_of::<FuseWriteReq>(),
            CommandId::MC_FUSE_LOCK_PARTITION => size_of::<FuseLockPartitionReq>(),
            _ => return Err(AuthorizationError),
        };

        // Canonical wire layout after the command body:
        //   [ nonce(48) | ecc_x(48) | ecc_y(48) | mldsa(2592) | sig(HybridSignature) ]
        // Signatures LAST (nonce + public keys precede them), matching the
        // caliptra-sw ProductionAuthDebugUnlockToken field order.
        let mut off = cmd_len;
        let wire_nonce: &[u8; AUTH_CMD_NONCE_LEN] = req
            .get(off..off + AUTH_CMD_NONCE_LEN)
            .ok_or(AuthorizationError)?
            .try_into()
            .map_err(|_| AuthorizationError)?;
        off += AUTH_CMD_NONCE_LEN;

        let ecc_pub_x: &[u8; ECC_P384_COORD_LEN] = req
            .get(off..off + ECC_P384_COORD_LEN)
            .ok_or(AuthorizationError)?
            .try_into()
            .map_err(|_| AuthorizationError)?;
        off += ECC_P384_COORD_LEN;

        let ecc_pub_y: &[u8; ECC_P384_COORD_LEN] = req
            .get(off..off + ECC_P384_COORD_LEN)
            .ok_or(AuthorizationError)?
            .try_into()
            .map_err(|_| AuthorizationError)?;
        off += ECC_P384_COORD_LEN;

        let mldsa_pub: &[u8; MLDSA87_PUB_KEY_LEN] = req
            .get(off..off + MLDSA87_PUB_KEY_LEN)
            .ok_or(AuthorizationError)?
            .try_into()
            .map_err(|_| AuthorizationError)?;
        off += MLDSA87_PUB_KEY_LEN;

        let sig_bytes = req
            .get(off..off + size_of::<HybridSignature>())
            .ok_or(AuthorizationError)?;
        let sig = HybridSignature::ref_from_bytes(sig_bytes).map_err(|_| AuthorizationError)?;

        let cmd_body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or(AuthorizationError)?;

        // Nonce gate + device_ops verify.
        self.verify_signatures(
            u32::from(cmd_id),
            cmd_body,
            wire_nonce,
            ecc_pub_x,
            ecc_pub_y,
            mldsa_pub,
            sig,
        )
        .await?;
        Ok(&req[..cmd_len])
    }

    /// Nonce gate shared by the mailbox and VDM paths: consume the stored
    /// one-time challenge, compare it to the wire nonce (absent/mismatch ->
    /// denied), then verify via `device_ops`.
    #[allow(clippy::too_many_arguments)]
    async fn verify_signatures(
        &mut self,
        cmd_id: u32,
        payload: &[u8],
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError> {
        let stored = CHALLENGE
            .lock(|state| state.borrow_mut().take())
            .ok_or(AuthorizationError)?;
        if *nonce != stored {
            return Err(AuthorizationError);
        }

        crate::caliptra_cmd_handler::device_ops::verify_authorized_signatures(
            cmd_id, payload, nonce, ecc_pub_x, ecc_pub_y, mldsa_pub, sig,
        )
        .await
        .map_err(|_| AuthorizationError)
    }

    fn take_challenge(&mut self) -> Option<[u8; AUTH_CMD_NONCE_LEN]> {
        CHALLENGE.lock(|state| state.borrow_mut().take())
    }

    fn set_challenge(&mut self, challenge: [u8; AUTH_CMD_NONCE_LEN]) {
        set_challenge(challenge);
    }
}
