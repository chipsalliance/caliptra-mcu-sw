// Licensed under the Apache-2.0 license

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct McuRuntimeCapabilities: u32 {
        const FLASH_BOOT = 1 << 0;
        const STREAMING_BOOT = 1 << 1;
        const FIRMWARE_UPDATE = 1 << 2;
        const SPDM_RESPONDER = 1 << 3;
        const MCTP_VDM_RESPONDER = 1 << 4;
        const USERSPACE_DEBUG_LOG = 1 << 5;
        const MCI_MAILBOX_SERVICE = 1 << 6;
        const DOE = 1 << 7;
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ExternalCommandCapabilities: u32 {
        const FIRMWARE_VERSION = command_capability(0x01);
        const DEVICE_CAPABILITIES = command_capability(0x02);
        const GET_DEBUG_LOG = command_capability(0x03);
        const CLEAR_DEBUG_LOG = command_capability(0x04);
        const GET_ATTESTATION = command_capability(0x05);
        const REQUEST_DEBUG_UNLOCK = command_capability(0x06);
        const AUTHORIZE_DEBUG_UNLOCK_TOKEN = command_capability(0x07);
        const EXPORT_ATTESTED_CSR = command_capability(0x08);
        const AUTHORIZED_COMMAND = command_capability(0x12);
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AuthorizedSubcommandCapabilities: u32 {
        const GET_AUTH_CHALLENGE = 1 << 0;
        const PROVISION_VENDOR_PK_HASH = 1 << 1;
        const FUSE_INCREASE_CALIPTRA_MIN_SVN = 1 << 2;
        const PROGRAM_FIELD_ENTROPY = 1 << 3;
        const FUSE_REVOKE_VENDOR_PUBLIC_KEY = 1 << 4;
        const FUSE_REVOKE_VENDOR_PK_HASH = 1 << 5;
        const FUSE_LOCK_PARTITION = 1 << 6;
        const PROVISION_OWNER_PK_HASH = 1 << 7;
        const DOT_LOCK = 1 << 8;
        const DOT_DISABLE = 1 << 9;
    }
}

const fn command_capability(command_code: u8) -> u32 {
    assert!(command_code >= 0x01 && command_code <= 0x20);
    1u32 << (command_code as u32 - 1)
}

pub const fn encode_capabilities(capabilities: u32) -> [u8; 4] {
    capabilities.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_domains_are_independent() {
        let features =
            McuRuntimeCapabilities::FLASH_BOOT | McuRuntimeCapabilities::MCTP_VDM_RESPONDER;
        let commands = ExternalCommandCapabilities::FIRMWARE_VERSION
            | ExternalCommandCapabilities::DEVICE_CAPABILITIES;

        assert_eq!(
            encode_capabilities(features.bits()),
            [0x00, 0x00, 0x00, 0x11]
        );
        assert_eq!(
            encode_capabilities(commands.bits()),
            [0x00, 0x00, 0x00, 0x03]
        );
    }

    #[test]
    fn all_reserved_command_codes_fit_in_the_top_level_bitmap() {
        assert_eq!(command_capability(0x01), 1);
        assert_eq!(command_capability(0x20), 1u32 << 31);
    }

    #[test]
    fn authorized_subcommand_assignments_are_stable() {
        assert_eq!(
            AuthorizedSubcommandCapabilities::GET_AUTH_CHALLENGE.bits(),
            1
        );
        assert_eq!(
            AuthorizedSubcommandCapabilities::PROGRAM_FIELD_ENTROPY.bits(),
            1 << 3
        );
        assert_eq!(
            AuthorizedSubcommandCapabilities::FUSE_LOCK_PARTITION.bits(),
            1 << 6
        );
        assert_eq!(
            AuthorizedSubcommandCapabilities::PROVISION_OWNER_PK_HASH.bits(),
            1 << 7
        );
        assert_eq!(AuthorizedSubcommandCapabilities::DOT_LOCK.bits(), 1 << 8);
        assert_eq!(AuthorizedSubcommandCapabilities::DOT_DISABLE.bits(), 1 << 9);
    }
}
