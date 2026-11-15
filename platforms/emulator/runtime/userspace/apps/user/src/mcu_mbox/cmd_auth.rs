// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{AuthorizationError, CommandAuthorizer};
use caliptra_mcu_libsyscall_caliptra::otp::Otp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_mbox_common::authorization::{AuthorizationMetadata, CommandAuthMode};
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_mcu_registers_generated::fuses;
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use mcu_caliptra_api::ScratchAlloc;

static CHALLENGE: Mutex<CriticalSectionRawMutex, RefCell<Option<[u8; AUTH_CMD_NONCE_LEN]>>> =
    Mutex::new(RefCell::new(None));

#[derive(Default)]
pub struct RuntimeCommandAuthorizer;

impl CommandAuthorizer for RuntimeCommandAuthorizer {
    fn device_ueid(&self) -> Result<[u8; 16], AuthorizationError> {
        let otp = Otp::<DefaultSyscalls>::new();
        // Manufacturer serial number occupies IDevID attribute words 12..16.
        let base = (fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_offset / 4) as u32 + 12;
        let mut ueid = [0; 16];
        for (index, word) in ueid.chunks_exact_mut(4).enumerate() {
            word.copy_from_slice(
                &otp.read_raw(base, index as u32)
                    .map_err(|_| AuthorizationError)?
                    .to_le_bytes(),
            );
        }
        if ueid == [0; 16] {
            return Err(AuthorizationError);
        }
        Ok(ueid)
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_signatures<Alloc: ScratchAlloc>(
        &self,
        alloc: &Alloc,
        cmd_id: u32,
        payload: &[u8],
        metadata: &AuthorizationMetadata,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        sig: &HybridSignature,
    ) -> Result<(), AuthorizationError> {
        if CommandAuthMode::from_nonce(nonce) == CommandAuthMode::ChallengeBound {
            let stored = self.take_challenge().ok_or(AuthorizationError)?;
            if *nonce != stored {
                return Err(AuthorizationError);
            }
        }

        crate::caliptra_cmd_handler::device_ops::verify_authorized_signatures(
            alloc, cmd_id, payload, metadata, nonce, ecc_pub_x, ecc_pub_y, mldsa_pub, sig,
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
