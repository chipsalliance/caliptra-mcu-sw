// Licensed under the Apache-2.0 license

#[cfg(not(hw_rev = "latest"))]
compile_error!("USB kernel stress tests require latest hardware");

use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_romtime::StaticRef;
use caliptra_mcu_tock_veer::timers::InternalTimers;
use caliptra_mcu_usb_common::{UsbParams, UsbStressDriver};
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::{Cell, RefCell};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks, Time};
use tock_registers::interfaces::{Readable, Writeable};

type TestAlarm = VirtualMuxAlarm<'static, InternalTimers<'static>>;
const START: u32 = 0x4353_5401;
const READY: u32 = 0x4353_5452;
const FAILED: u32 = 0x4353_5446;

struct StressService {
    driver: RefCell<UsbStressDriver>,
    alarm: &'static TestAlarm,
    mci: StaticRef<mci::regs::Mci>,
    started: Cell<bool>,
    failed: Cell<bool>,
}

impl StressService {
    fn schedule(&self) {
        // Complete deferred EP0 status actions within SET_ADDRESS recovery time.
        self.alarm
            .set_alarm(self.alarm.now(), self.alarm.ticks_from_us(100));
    }
}

impl AlarmClient for StressService {
    fn alarm(&self) {
        if self.failed.get() {
            return;
        }
        let result = if self.started.get() {
            self.driver.borrow_mut().poll().map(|_| ())
        } else if self.mci.mci_reg_generic_input_wires[0].get() == START {
            self.driver.borrow_mut().initialize()
        } else {
            self.schedule();
            return;
        };
        match result {
            Ok(()) => {
                if !self.started.replace(true) {
                    caliptra_mcu_romtime::println!("[usb-stress-kernel] Device 0 CST1 ready");
                    self.mci.mci_reg_generic_output_wires[1].set(READY);
                }
                self.schedule();
            }
            Err(error) => {
                caliptra_mcu_romtime::println!("[usb-stress-kernel] Device 0 failed: {:?}", error);
                self.mci.mci_reg_generic_output_wires[1].set(FAILED);
                self.failed.set(true);
            }
        }
    }
}

/// # Safety
/// Call once during kernel boot, before alarm dispatch begins.
pub(crate) unsafe fn start(mux: &'static MuxAlarm<'static, InternalTimers<'static>>) {
    let alarm = kernel::static_init!(TestAlarm, TestAlarm::new(mux));
    alarm.setup();
    let params = UsbParams {
        shared_phy_owner: true,
        registers: unsafe { StaticRef::new(0xa420_0000 as *const _) },
        packet_memory: unsafe { StaticRef::new(0xa430_0000 as *const _) },
        vendor_id: 0x0424,
        product_id: 0x0007,
        device_revision: 0x0102,
        self_powered: true,
        max_power_2ma: 0,
        remote_wakeup: false,
        force_full_speed: false,
        enable_hub: true,
        enable_logs: true,
        poll_limit: 1_000_000,
    };
    let service = kernel::static_init!(
        StressService,
        StressService {
            driver: RefCell::new(UsbStressDriver::new(params)),
            alarm,
            mci: unsafe { StaticRef::new(crate::MCU_MEMORY_MAP.mci_offset as *const _) },
            started: Cell::new(false),
            failed: Cell::new(false),
        }
    );
    service.mci.mci_reg_generic_output_wires[1].set(0);
    alarm.set_alarm_client(service);
    service.schedule();
}
