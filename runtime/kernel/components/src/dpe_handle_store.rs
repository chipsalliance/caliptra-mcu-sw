// Licensed under the Apache-2.0 license

//! Component for the DPE Handle Storage capsule.
//!
//! Instantiates a [`DpeHandleStore`] capsule from a reserved SRAM subregion
//! and registers it with the board kernel.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let dpe_handle_store = DpeHandleStoreComponent::new(
//!     board_kernel,
//!     caliptra_mcu_capsules_runtime::dpe_handle_store::DRIVER_NUM,
//!     dpe_sram_subregion,
//! )
//! .finalize(dpe_handle_store_component_static!());
//! ```

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

/// Allocate static storage for the `DpeHandleStore` capsule.
#[macro_export]
macro_rules! dpe_handle_store_component_static {
    () => {{
        kernel::static_buf!(caliptra_mcu_capsules_runtime::dpe_handle_store::DpeHandleStore)
    }};
}

pub struct DpeHandleStoreComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    exported_cdi_capacity: usize,
    mem: &'static mut [u8],
}

impl DpeHandleStoreComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mem: &'static mut [u8],
    ) -> Self {
        Self::with_exported_cdi_capacity(
            board_kernel,
            driver_num,
            mem,
            caliptra_mcu_capsules_runtime::dpe_handle_store::DEFAULT_EXPORTED_CDI_CAPACITY,
        )
    }

    pub fn with_exported_cdi_capacity(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mem: &'static mut [u8],
        exported_cdi_capacity: usize,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            exported_cdi_capacity,
            mem,
        }
    }
}

impl Component for DpeHandleStoreComponent {
    type StaticInput =
        &'static mut MaybeUninit<caliptra_mcu_capsules_runtime::dpe_handle_store::DpeHandleStore>;

    type Output = &'static caliptra_mcu_capsules_runtime::dpe_handle_store::DpeHandleStore;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        static_buffer.write(
            caliptra_mcu_capsules_runtime::dpe_handle_store::DpeHandleStore::with_exported_cdi_capacity(
                self.driver_num,
                self.mem,
                self.exported_cdi_capacity,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
            ),
        )
    }
}
