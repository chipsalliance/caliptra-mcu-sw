// Licensed under the Apache-2.0 license

use caliptra_mcu_registers_generated::mci::bits::MboxTargetStatus;

/// Completion follows the selected mailbox's DONE-bit or status-only contract.
pub fn is_complete(value: u32) -> bool {
    #[cfg(hw_capability = "mbox-target-done")]
    {
        value & MboxTargetStatus::Done::SET.value != 0
    }
    #[cfg(hw_capability = "mbox-status-completion")]
    {
        value & MboxTargetStatus::Status::SET.value != MboxTargetStatus::Status::CmdBusy.value
    }
}

pub fn completion_value(status: u32) -> u32 {
    let value = MboxTargetStatus::Status.val(status).value;
    #[cfg(hw_capability = "mbox-target-done")]
    {
        value | MboxTargetStatus::Done::SET.value
    }
    #[cfg(hw_capability = "mbox-status-completion")]
    {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_matches_selected_hardware() {
        assert!(!is_complete(MboxTargetStatus::Status::CmdBusy.value));
        for status in [
            MboxTargetStatus::Status::DataReady.value,
            MboxTargetStatus::Status::CmdComplete.value,
            MboxTargetStatus::Status::CmdFailure.value,
        ] {
            let value = completion_value(status);
            assert!(is_complete(value));
            assert_eq!(value & MboxTargetStatus::Status::SET.value, status);
            #[cfg(hw_capability = "mbox-target-done")]
            assert!(!is_complete(status));
            #[cfg(hw_capability = "mbox-status-completion")]
            assert_eq!(value, status);
        }
    }
}
