// Licensed under the Apache-2.0 license

use romtime::handoff::HandoffData;
#[cfg(feature = "ocp-lock")]
use romtime::ocp_lock::HekState;

pub struct HandOff {
    data: HandoffData,
}

impl HandOff {
    /// Read the handoff data from DCCM.
    pub fn from_dccm() -> Option<Self> {
        let data = unsafe {
            romtime::println!(
                "[mcu-runtime] Reading handoff table from DCCM at {:p}",
                &raw const romtime::handoff::HANDOFF
            );
            romtime::handoff::HANDOFF
        };

        if data.rom.fht_marker == romtime::handoff::FHT_MARKER {
            Some(Self { data })
        } else {
            None
        }
    }

    /// Get the HEK state from the handoff table.
    #[cfg(feature = "ocp-lock")]
    pub fn hek_state(&self) -> HekState {
        self.data.rom.hek_state
    }

    /// Get the FHT marker.
    pub fn marker(&self) -> u32 {
        self.data.rom.fht_marker
    }

    /// Get the address of the handoff table.
    pub fn addr(&self) -> *const HandoffData {
        &raw const romtime::handoff::HANDOFF
    }
}
