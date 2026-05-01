// Licensed under the Apache-2.0 license
use caliptra_mcu_common_commands::{AuthorizationResult, CommandAuthorizer};

#[derive(Default)]
pub struct MockCommandAuthorizer {
    challenge: Option<[u8; 32]>,
}

impl CommandAuthorizer for MockCommandAuthorizer {
    fn is_authorized<'a>(
        &self,
        _cmd_id: caliptra_mcu_mbox_common::messages::CommandId,
        req: &'a [u8],
    ) -> AuthorizationResult<&'a [u8]> {
        Ok(req)
    }

    fn take_challenge(&mut self) -> Option<[u8; 32]> {
        self.challenge.take()
    }

    fn set_challenge(&mut self, challenge: [u8; 32]) {
        self.challenge = Some(challenge)
    }
}
