// Licensed under the Apache-2.0 license

// Component for the flash-based logging capsule.

use caliptra_mcu_capsules_runtime::logging;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;
use kernel::hil::log::{LogRead, LogWrite};

#[macro_export]
macro_rules! logging_flash_component_static {
    ($F:ty, $buf_len:expr $(,)?) => {{
        let page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let read_page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let log = kernel::static_buf!(
            caliptra_mcu_capsules_runtime::logging::logging_flash::Log<'static, $F>
        );
        let driver = kernel::static_buf!(
            caliptra_mcu_capsules_runtime::logging::driver::LoggingFlashDriver<'static>
        );
        let buffer = kernel::static_buf!([u8; $buf_len]);

        (page, read_page, log, driver, buffer)
    }};
}

#[macro_export]
macro_rules! instantiate_logging_flash {
    (
        $list_macro:tt,
        $instances:ident,
        $kernel:expr,
        $mux:expr,
        $flash_ctrl_ty:ty,
        $page_size:expr,
        $circular:expr
    ) => {{
        macro_rules! assign_logging_flash {
            ($idx:expr, $_var:ident, $partition:ident) => {
                let log_fl_user = components::flash::FlashUserComponent::new($mux)
                    .finalize(components::flash_user_component_static!($flash_ctrl_ty));
                $instances[$idx] = Some(
                    caliptra_mcu_components::logging::LoggingFlashComponent::new(
                        $kernel,
                        $partition.driver_num as usize,
                        log_fl_user,
                        $partition.base_page($page_size),
                        $partition.num_pages($page_size),
                        $circular,
                    )
                    .finalize(caliptra_mcu_components::logging_flash_component_static!(
                        virtual_flash::FlashUser<'static, $flash_ctrl_ty>,
                        caliptra_mcu_capsules_runtime::logging::driver::BUF_LEN
                    )),
                );
            };
        }

        $list_macro!(assign_logging_flash);
    }};
}

pub struct LoggingFlashComponent<
    F: 'static
        + hil::flash::Flash
        + hil::flash::HasClient<'static, logging::logging_flash::Log<'static, F>>,
> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    flash_drv: &'static F,
    base_page: usize,
    num_pages: usize,
    circular: bool,
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<'static, logging::logging_flash::Log<'static, F>>,
    > LoggingFlashComponent<F>
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        flash_drv: &'static F,
        base_page: usize,
        num_pages: usize,
        circular: bool,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            flash_drv,
            base_page,
            num_pages,
            circular,
        }
    }
}

impl<F> Component for LoggingFlashComponent<F>
where
    F: 'static
        + hil::flash::Flash
        + hil::flash::HasClient<'static, logging::logging_flash::Log<'static, F>>,
{
    type StaticInput = (
        &'static mut MaybeUninit<<F as hil::flash::Flash>::Page>,
        &'static mut MaybeUninit<<F as hil::flash::Flash>::Page>,
        &'static mut MaybeUninit<logging::logging_flash::Log<'static, F>>,
        &'static mut MaybeUninit<logging::driver::LoggingFlashDriver<'static>>,
        &'static mut MaybeUninit<[u8; logging::driver::BUF_LEN]>,
    );

    type Output = &'static logging::driver::LoggingFlashDriver<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let buffer = static_buffer.4.write([0; logging::driver::BUF_LEN]);
        let pagebuffer = static_buffer
            .0
            .write(<F as hil::flash::Flash>::Page::default());
        let read_pagebuffer = static_buffer
            .1
            .write(<F as hil::flash::Flash>::Page::default());

        let log = static_buffer.2.write(logging::logging_flash::Log::new(
            self.base_page,
            self.num_pages,
            self.flash_drv,
            pagebuffer,
            read_pagebuffer,
            self.circular,
        ));
        kernel::deferred_call::DeferredCallClient::register(log);
        hil::flash::HasClient::set_client(self.flash_drv, log);

        let driver = static_buffer
            .3
            .write(logging::driver::LoggingFlashDriver::new(
                log,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
                buffer,
            ));

        log.set_read_client(driver);
        log.set_append_client(driver);

        log.init();

        driver
    }
}
