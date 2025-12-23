// Licensed under the Apache-2.0 license

// Component for flash partition driver.

use capsules_runtime::flash_partition::FlashPartition;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;

#[macro_export]
macro_rules! instantiate_flash_partitions {
    (
        $partition_list_macro:tt,
        $flash_partitions:ident,
        $kernel:expr,
        $mux:expr,
        $flash_ctrl_ty:ty
    ) => {{
        macro_rules! assign_partition {
            ($index:tt, $var:ident, $partition:ident) => {
                let image_par_fl_user = components::flash::FlashUserComponent::new($mux)
                    .finalize(components::flash_user_component_static!($flash_ctrl_ty));

                $flash_partitions[$index] = Some(
                    mcu_components::flash_partition::FlashPartitionComponent::new(
                        $kernel,
                        $partition.driver_num as usize,
                        image_par_fl_user,
                        $partition.offset,
                        $partition.size,
                    )
                    .finalize(flash_partition_component_static!(
                        virtual_flash::FlashUser<'static, $flash_ctrl_ty>,
                        capsules_runtime::flash_partition::BUF_LEN
                    )),
                );
            };
        }

        $partition_list_macro!(assign_partition);
    }};
}

#[macro_export]
macro_rules! flash_partition_component_static {
    ($F:ty, $buf_len:expr $(,)?) => {{
        let page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let fs_to_pages = kernel::static_buf!(
            flash_driver::flash_storage_to_pages::FlashStorageToPages<'static, $F>
        );
        let fs = kernel::static_buf!(capsules_runtime::flash_partition::FlashPartition<'static>);
        let buffer = kernel::static_buf!([u8; $buf_len]);

        (page, fs_to_pages, fs, buffer)
    }};
}

pub struct FlashPartitionComponent<
    F: 'static
        + hil::flash::Flash
        + hil::flash::HasClient<
            'static,
            flash_driver::flash_storage_to_pages::FlashStorageToPages<'static, F>,
        >,
> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    flash: &'static F,
    start_address: usize,
    length: usize,
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<
                'static,
                flash_driver::flash_storage_to_pages::FlashStorageToPages<'static, F>,
            >,
    > FlashPartitionComponent<F>
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        flash: &'static F,
        start_address: usize,
        length: usize,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            flash,
            start_address,
            length,
        }
    }
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<
                'static,
                flash_driver::flash_storage_to_pages::FlashStorageToPages<'static, F>,
            >,
    > Component for FlashPartitionComponent<F>
{
    type StaticInput = (
        &'static mut MaybeUninit<<F as hil::flash::Flash>::Page>,
        &'static mut MaybeUninit<
            flash_driver::flash_storage_to_pages::FlashStorageToPages<'static, F>,
        >,
        &'static mut MaybeUninit<FlashPartition<'static>>,
        &'static mut MaybeUninit<[u8; capsules_runtime::flash_partition::BUF_LEN]>,
    );

    type Output = &'static FlashPartition<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let buffer = static_buffer
            .3
            .write([0; capsules_runtime::flash_partition::BUF_LEN]);

        let flash_pagebuffer = static_buffer
            .0
            .write(<F as hil::flash::Flash>::Page::default());

        let fs_to_pages = static_buffer.1.write(
            flash_driver::flash_storage_to_pages::FlashStorageToPages::new(
                self.flash,
                flash_pagebuffer,
            ),
        );
        hil::flash::HasClient::set_client(self.flash, fs_to_pages);

        let flash_partition =
            static_buffer
                .2
                .write(capsules_runtime::flash_partition::FlashPartition::new(
                    fs_to_pages,
                    self.driver_num,
                    self.board_kernel.create_grant(self.driver_num, &grant_cap),
                    self.start_address,
                    self.length,
                    buffer,
                ));
        flash_driver::hil::FlashStorage::set_client(fs_to_pages, flash_partition);
        flash_partition
    }
}
