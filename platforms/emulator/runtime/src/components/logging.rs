// Licensed under the Apache-2.0 license

// Component for flash-based logging driver.

use capsules_emulator::logging;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;
use kernel::hil::log::{LogRead, LogWrite};

const LOG_FLASH_BASE_ADDR: u32 = mcu_config_emulator::flash::LOGGING_FLASH_CONFIG.base_addr;

#[macro_export]
macro_rules! logging_flash_component_static {
    ($F:ty, $buf_len:expr $(,)?) => {{
        let page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let log = kernel::static_buf!(capsules_emulator::logging::logging_flash::Log<'static, $F>);
        let driver =
            kernel::static_buf!(capsules_emulator::logging::driver::LoggingFlashDriver<'static>);
        let buffer = kernel::static_buf!([u8; $buf_len]);

        (page, log, driver, buffer)
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
    log_volume: &'static [u8],
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
        log_volume: &'static [u8],
        circular: bool,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            flash_drv,
            log_volume,
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
        &'static mut MaybeUninit<logging::logging_flash::Log<'static, F>>,
        &'static mut MaybeUninit<logging::driver::LoggingFlashDriver<'static>>,
        &'static mut MaybeUninit<[u8; logging::driver::BUF_LEN]>,
    );

    type Output = &'static logging::driver::LoggingFlashDriver<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let buffer = static_buffer.3.write([0; logging::driver::BUF_LEN]);
        let flash_pagebuffer = static_buffer
            .0
            .write(<F as hil::flash::Flash>::Page::default());

        // Instantiate Log
        let log = static_buffer.1.write(logging::logging_flash::Log::new(
            self.log_volume,
            self.flash_drv,
            flash_pagebuffer,
            self.circular,
        ));
        log.set_flash_base_address(LOG_FLASH_BASE_ADDR);
        kernel::deferred_call::DeferredCallClient::register(log);
        hil::flash::HasClient::set_client(self.flash_drv, log);

        // Instantiate LoggingFlashDriver
        let driver = static_buffer
            .2
            .write(logging::driver::LoggingFlashDriver::new(
                log,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
                buffer,
            ));

        log.set_read_client(driver);
        log.set_append_client(driver);
        driver
    }
}
