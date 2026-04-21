// Licensed under the Apache-2.0 license
use caliptra_mcu_external_cmds_common::CommandAuthorizer;

pub struct MockCommandAuthorizer;

impl CommandAuthorizer for MockCommandAuthorizer {
    fn is_authorized<'a>(
        &self,
        _cmd_id: caliptra_mcu_mbox_common::messages::CommandId,
        req: &'a [u8],
    ) -> Result<&'a [u8], caliptra_mcu_external_cmds_common::AuthorizationError> {
        Ok(req)
    }
}
