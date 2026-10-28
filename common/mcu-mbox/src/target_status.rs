// Licensed under the Apache-2.0 license

use caliptra_mcu_registers_generated::mci::bits::MboxTargetStatus;

/// 2.1 requires DONE; latest signals completion with any non-BUSY status.
pub fn is_complete(value: u32) -> bool {
    #[cfg(hw_rev = "2.1")]
    {
        value & MboxTargetStatus::Done::SET.value != 0
    }
    #[cfg(hw_rev = "latest")]
    {
        value & MboxTargetStatus::Status::SET.value != MboxTargetStatus::Status::CmdBusy.value
    }
}

pub fn completion_value(status: u32) -> u32 {
    let value = MboxTargetStatus::Status.val(status).value;
    #[cfg(hw_rev = "2.1")]
    {
        value | MboxTargetStatus::Done::SET.value
    }
    #[cfg(hw_rev = "latest")]
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
            #[cfg(hw_rev = "2.1")]
            assert!(!is_complete(status));
            #[cfg(hw_rev = "latest")]
            assert_eq!(value, status);
        }
    }
}
