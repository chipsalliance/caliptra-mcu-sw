// Licensed under the Apache-2.0 license

//! Component for the Software PCR Store capsule.
//!
//! Instantiates a [`PcrStore`] capsule from a reserved SRAM subregion
//! and registers it with the board kernel.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let pcr_store = PcrStoreComponent::new(
//!     board_kernel,
//!     caliptra_mcu_capsules_runtime::pcr_store::DRIVER_NUM,
//!     pcr_sram_subregion,
//! )
//! .finalize(pcr_store_component_static!());
//! ```

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

/// Allocate static storage for the `PcrStore` capsule.
#[macro_export]
macro_rules! pcr_store_component_static {
    () => {{
        kernel::static_buf!(caliptra_mcu_capsules_runtime::pcr_store::PcrStore)
    }};
}

pub struct PcrStoreComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mem: &'static mut [u8],
}

impl PcrStoreComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mem: &'static mut [u8],
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            mem,
        }
    }
}

impl Component for PcrStoreComponent {
    type StaticInput = &'static mut MaybeUninit<caliptra_mcu_capsules_runtime::pcr_store::PcrStore>;

    type Output = &'static caliptra_mcu_capsules_runtime::pcr_store::PcrStore;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        static_buffer.write(caliptra_mcu_capsules_runtime::pcr_store::PcrStore::new(
            self.driver_num,
            self.mem,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ))
    }
}
