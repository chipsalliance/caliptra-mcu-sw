// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{AuthorizationError, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotDisableReq, DotLockReq, DotRotateReq, FuseIncreaseCaliptraMinSvnReq,
    FuseLockPartitionReq, FuseReadReq, FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq,
    FuseWriteReq, HybridSignature, MailboxReqHeader, McuFeProgReq, ProvisionOwnerPkHashReq,
    ProvisionVendorPkHashReq, AUTH_CMD_NONCE_LEN,
};
use core::cell::RefCell;
use core::mem::{offset_of, size_of};
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use mcu_caliptra_api::ApiAlloc;
use zerocopy::{FromBytes, Immutable, KnownLayout};

extern crate alloc;

/// Length of one P-384 public-key coordinate.
const ECC_P384_COORD_LEN: usize = 48;
/// Length of the ML-DSA-87 public key.
const MLDSA87_PUB_KEY_LEN: usize = 2592;

/// Fixed authorization block following the command-specific body; identical for
/// every authorized command. Signatures LAST, matching the caliptra-sw
/// `ProductionAuthDebugUnlockToken` order and the `FeProgVdmReq`/`FeProgRequest` twins.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct AuthorizationBlock {
    /// Freshness nonce echoed back from `GetAuthCmdChallenge`.
    nonce: [u8; AUTH_CMD_NONCE_LEN],
    /// ECC P-384 verifier public key X coordinate (hashed into the anchor).
    ecc_pub_x: [u8; ECC_P384_COORD_LEN],
    /// ECC P-384 verifier public key Y coordinate.
    ecc_pub_y: [u8; ECC_P384_COORD_LEN],
    /// ML-DSA-87 verifier public key.
    mldsa_pub: [u8; MLDSA87_PUB_KEY_LEN],
    /// Hybrid signature (ECDSA P-384 r||s then ML-DSA-87), placed LAST.
    sig: HybridSignature,
}

// Canonical wire layout: nonce(48) | ecc_pub_x(48) | ecc_pub_y(48) | mldsa_pub(2592) | sig(4724).
// Per-field offsets, not just size: a size-only assert passes for any field permutation.
const _: () = assert!(
    size_of::<AuthorizationBlock>()
        == AUTH_CMD_NONCE_LEN
            + ECC_P384_COORD_LEN
            + ECC_P384_COORD_LEN
            + MLDSA87_PUB_KEY_LEN
            + size_of::<HybridSignature>()
);
const _: () = assert!(offset_of!(AuthorizationBlock, nonce) == 0);
const _: () = assert!(offset_of!(AuthorizationBlock, ecc_pub_x) == AUTH_CMD_NONCE_LEN);
const _: () = assert!(
    offset_of!(AuthorizationBlock, ecc_pub_y)
        == offset_of!(AuthorizationBlock, ecc_pub_x) + ECC_P384_COORD_LEN
);
const _: () = assert!(
    offset_of!(AuthorizationBlock, mldsa_pub)
        == offset_of!(AuthorizationBlock, ecc_pub_y) + ECC_P384_COORD_LEN
);
const _: () = assert!(
    offset_of!(AuthorizationBlock, sig)
        == offset_of!(AuthorizationBlock, mldsa_pub) + MLDSA87_PUB_KEY_LEN
);

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
        alloc: &Alloc,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> Result<&'a [u8], AuthorizationError> {
        let cmd_len = match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => size_of::<ProvisionVendorPkHashReq>(),
            CommandId::MC_PROVISION_OWNER_PK_HASH => size_of::<ProvisionOwnerPkHashReq>(),
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                size_of::<FuseIncreaseCaliptraMinSvnReq>()
            }
            CommandId::MC_FE_PROG => size_of::<McuFeProgReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => size_of::<FuseRevokeVendorPubKeyReq>(),
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => size_of::<FuseRevokeVendorPkHashReq>(),
            CommandId::MC_FUSE_READ => size_of::<FuseReadReq>(),
            CommandId::MC_FUSE_WRITE => size_of::<FuseWriteReq>(),
            CommandId::MC_FUSE_LOCK_PARTITION => size_of::<FuseLockPartitionReq>(),
            CommandId::MC_DEVICE_OWNERSHIP_TRANSFER => {
                let subcommand = req
                    .get(size_of::<MailboxReqHeader>()..size_of::<MailboxReqHeader>() + 4)
                    .ok_or(AuthorizationError)?;
                match u32::from_le_bytes(subcommand.try_into().map_err(|_| AuthorizationError)?) {
                    value if value == CommandId::MC_DOT_LOCK.0 => size_of::<DotLockReq>(),
                    value if value == CommandId::MC_DOT_DISABLE.0 => size_of::<DotDisableReq>(),
                    value if value == CommandId::MC_DOT_ROTATE.0 => size_of::<DotRotateReq>(),
                    _ => return Err(AuthorizationError),
                }
            }
            _ => return Err(AuthorizationError),
        };

        // Tail starts at `cmd_len`, which INCLUDES the MailboxReqHeader; `cmd_body`
        // below starts after it, so the two bases differ deliberately.
        // `ref_from_prefix` keeps the old walk's tolerance of trailing bytes
        // (`ref_from_bytes` is exact-size; `ref_from_suffix` would silently shift the window).
        let (auth, _trailing) =
            AuthorizationBlock::ref_from_prefix(req.get(cmd_len..).ok_or(AuthorizationError)?)
                .map_err(|_| AuthorizationError)?;
        let AuthorizationBlock {
            nonce: wire_nonce,
            ecc_pub_x,
            ecc_pub_y,
            mldsa_pub,
            sig,
        } = auth;

        let cmd_body = req
            .get(size_of::<MailboxReqHeader>()..cmd_len)
            .ok_or(AuthorizationError)?;

        // Nonce gate + device_ops verify.
        self.verify_signatures(
            alloc,
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
    async fn verify_signatures<Alloc: ApiAlloc>(
        &mut self,
        alloc: &Alloc,
        cmd_id: u32,
        payload: &[u8],
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError> {
        let stored = self.take_challenge().ok_or(AuthorizationError)?;
        if *nonce != stored {
            return Err(AuthorizationError);
        }

        crate::caliptra_cmd_handler::device_ops::verify_authorized_signatures(
            alloc, cmd_id, payload, nonce, ecc_pub_x, ecc_pub_y, mldsa_pub, sig,
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
