// Licensed under the Apache-2.0 license

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

use caliptra_mcu_capsules_runtime::flash_partition::FlashPartition;
use caliptra_mcu_capsules_runtime::memory_flash::MemoryFlash;
use caliptra_mcu_flash_driver::hil::FlashStorage;

#[macro_export]
macro_rules! memory_flash_partition_component_static {
    () => {{
        (
            kernel::static_buf!(caliptra_mcu_capsules_runtime::memory_flash::MemoryFlash<'static>),
            kernel::static_buf!(
                caliptra_mcu_capsules_runtime::flash_partition::FlashPartition<'static>
            ),
            kernel::static_buf!([u8; caliptra_mcu_capsules_runtime::flash_partition::BUF_LEN]),
        )
    }};
}

pub struct MemoryFlashPartitionComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    memory: &'static mut [u8],
}

impl MemoryFlashPartitionComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        memory: &'static mut [u8],
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            memory,
        }
    }
}

impl Component for MemoryFlashPartitionComponent {
    type StaticInput = (
        &'static mut MaybeUninit<MemoryFlash<'static>>,
        &'static mut MaybeUninit<FlashPartition<'static>>,
        &'static mut MaybeUninit<[u8; caliptra_mcu_capsules_runtime::flash_partition::BUF_LEN]>,
    );
    type Output = &'static FlashPartition<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let memory_len = self.memory.len();
        let flash = static_buffer.0.write(MemoryFlash::new(self.memory));
        kernel::deferred_call::DeferredCallClient::register(flash);
        let buffer = static_buffer
            .2
            .write([0; caliptra_mcu_capsules_runtime::flash_partition::BUF_LEN]);
        let partition = static_buffer.1.write(FlashPartition::new(
            flash,
            self.driver_num,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
            0,
            memory_len,
            buffer,
        ));
        flash.set_client(partition);
        partition
    }
}
