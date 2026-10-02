// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{AuthorizationError, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use mcu_caliptra_api::ApiAlloc;

static CHALLENGE: Mutex<CriticalSectionRawMutex, RefCell<Option<[u8; AUTH_CMD_NONCE_LEN]>>> =
    Mutex::new(RefCell::new(None));

#[derive(Default)]
pub struct MockCommandAuthorizer;

impl CommandAuthorizer for MockCommandAuthorizer {
    #[allow(clippy::too_many_arguments)]
    async fn verify_signatures<Alloc: ApiAlloc>(
        &self,
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
            alloc, cmd_id, payload, nonce, *ecc_pub_x, *ecc_pub_y, mldsa_pub, sig,
        )
        .await
        .map_err(|_| AuthorizationError)
    }

    fn take_challenge(&self) -> Option<[u8; AUTH_CMD_NONCE_LEN]> {
        CHALLENGE.lock(|state| state.borrow_mut().take())
    }

    fn set_challenge(&self, challenge: [u8; AUTH_CMD_NONCE_LEN]) {
        CHALLENGE.lock(|state| *state.borrow_mut() = Some(challenge));
    }
}
