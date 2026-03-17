// Licensed under the Apache-2.0 license

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tock_registers::interfaces::Readable;

use emulator_registers_generated::usbdev::{UsbdevGenerated, UsbdevPeripheral};

#[allow(dead_code)]
pub struct UsbDevState {
    pub(crate) generated: UsbdevGenerated,

    pub(crate) av_setup_fifo: VecDeque<u8>,
    pub(crate) av_out_fifo: VecDeque<u8>,
    pub(crate) rx_fifo: VecDeque<RxFifoEntry>,

    pub(crate) frame: u16,

    pub(crate) out_data_toggle: u16,
    pub(crate) in_data_toggle: u16,

    pub(crate) in_sending: u16,

    pub(crate) hw_intr_state: u32,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct RxFifoEntry {
    pub buffer: u8,
    pub size: u8,
    pub setup: bool,
    pub ep: u8,
}

impl UsbDevState {
    fn new() -> Self {
        Self {
            generated: UsbdevGenerated::new(),
            av_setup_fifo: VecDeque::new(),
            av_out_fifo: VecDeque::new(),
            rx_fifo: VecDeque::new(),
            frame: 0,
            out_data_toggle: 0,
            in_data_toggle: 0,
            in_sending: 0,
            hw_intr_state: 0,
        }
    }
}

/// Emulator peripheral for the examplar USB 2.0 Full-Speed device IP block.
///
/// Implements the [`UsbdevPeripheral`] trait and is owned by [`AutoRootBus`], which routes
/// firmware MMIO accesses at `0x0900_0000` to this peripheral. All mutable device state
/// lives behind an `Arc<Mutex<UsbDevState>>` shared with [`UsbHostController`], allowing
/// a test thread to inject USB transactions while the emulated CPU reads/writes registers.
///
/// # Construction
///
/// ```ignore
/// let periph = UsbDevPeriph::new();
/// let host = periph.host_controller();  // clone the shared state handle
/// // Pass `periph` to AutoRootBus, keep `host` for the test harness.
/// ```
///
/// [`AutoRootBus`]: emulator_registers_generated::root_bus::AutoRootBus
pub struct UsbDevPeriph {
    state: Arc<Mutex<UsbDevState>>,
}

impl Default for UsbDevPeriph {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDevPeriph {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(UsbDevState::new())),
        }
    }

    /// Create a [`UsbHostController`] handle that shares this peripheral's state.
    ///
    /// Call this before passing `self` to `AutoRootBus`, since the bus takes ownership.
    pub fn host_controller(&self) -> UsbHostController {
        UsbHostController {
            state: Arc::clone(&self.state),
        }
    }
}

/// Host-side handle for injecting USB transactions into the emulated device.
///
/// Obtained via [`UsbDevPeriph::host_controller()`] before the peripheral is handed to
/// `AutoRootBus`. This handle is `Clone` and `Send`, so it can be moved to a test thread
/// that simulates a USB host while the emulated firmware runs on the main emulator loop.
///
/// The typical test flow is:
/// 1. Poll [`device_enabled()`](Self::device_enabled) until firmware sets `usbctrl.enable`.
/// 2. Inject SETUP/OUT/IN transactions
/// 3. Assert expected responses.
#[derive(Clone)]
pub struct UsbHostController {
    state: Arc<Mutex<UsbDevState>>,
}

impl UsbHostController {
    /// Returns `true` if firmware has set the `enable` bit in the `usbctrl` register,
    /// indicating the device is initialized and ready to communicate.
    pub fn device_enabled(&self) -> bool {
        use registers_generated::usbdev::bits::Usbctrl;
        let mut state = self.state.lock().unwrap();
        let usbctrl = state.generated.read_usbctrl();
        usbctrl.reg.is_set(Usbctrl::Enable)
    }
}

// The default `UsbdevPeripheral::generated()` dispatch returns `Option<&mut UsbdevGenerated>`,
// but we cannot return a mutable reference through a `MutexGuard` (the borrow doesn't outlive
// the lock). These macros generate per-method overrides that acquire the lock and delegate
// to the inner `UsbdevGenerated`, avoiding the lifetime issue.
macro_rules! delegate_read {
    ($method:ident, $reg:ident) => {
        fn $method(
            &mut self,
        ) -> caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::usbdev::bits::$reg::Register,
        > {
            let mut state = self.state.lock().unwrap();
            state.generated.$method()
        }
    };
}

macro_rules! delegate_write {
    ($method:ident, $reg:ident) => {
        fn $method(
            &mut self,
            val: caliptra_emu_bus::ReadWriteRegister<
                u32,
                registers_generated::usbdev::bits::$reg::Register,
            >,
        ) {
            let mut state = self.state.lock().unwrap();
            state.generated.$method(val);
        }
    };
}

impl UsbdevPeripheral for UsbDevPeriph {
    fn poll(&mut self) {}
    fn warm_reset(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.generated.warm_reset();
    }
    fn update_reset(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.generated.update_reset();
    }

    delegate_read!(read_intr_state, IntrState);
    delegate_write!(write_intr_state, IntrState);
    delegate_read!(read_intr_enable, IntrEnable);
    delegate_write!(write_intr_enable, IntrEnable);
    delegate_write!(write_intr_test, IntrTest);
    delegate_write!(write_alert_test, AlertTest);
    delegate_read!(read_usbctrl, Usbctrl);
    delegate_write!(write_usbctrl, Usbctrl);
    delegate_read!(read_ep_out_enable, EpOutEnable);
    delegate_write!(write_ep_out_enable, EpOutEnable);
    delegate_read!(read_ep_in_enable, EpInEnable);
    delegate_write!(write_ep_in_enable, EpInEnable);
    delegate_read!(read_usbstat, Usbstat);
    delegate_write!(write_avoutbuffer, Avoutbuffer);
    delegate_write!(write_avsetupbuffer, Avsetupbuffer);
    delegate_read!(read_rxfifo, Rxfifo);
    delegate_read!(read_rxenable_setup, RxenableSetup);
    delegate_write!(write_rxenable_setup, RxenableSetup);
    delegate_read!(read_rxenable_out, RxenableOut);
    delegate_write!(write_rxenable_out, RxenableOut);
    delegate_read!(read_set_nak_out, SetNakOut);
    delegate_write!(write_set_nak_out, SetNakOut);
    delegate_read!(read_in_sent, InSent);
    delegate_write!(write_in_sent, InSent);
    delegate_read!(read_out_stall, OutStall);
    delegate_write!(write_out_stall, OutStall);
    delegate_read!(read_in_stall, InStall);
    delegate_write!(write_in_stall, InStall);

    fn read_configin_0(
        &mut self,
        index: usize,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::usbdev::bits::Configin0::Register,
    > {
        let mut state = self.state.lock().unwrap();
        state.generated.read_configin_0(index)
    }
    fn write_configin_0(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::usbdev::bits::Configin0::Register,
        >,
        index: usize,
    ) {
        let mut state = self.state.lock().unwrap();
        state.generated.write_configin_0(val, index);
    }

    delegate_read!(read_out_iso, OutIso);
    delegate_write!(write_out_iso, OutIso);
    delegate_read!(read_in_iso, InIso);
    delegate_write!(write_in_iso, InIso);
    delegate_read!(read_out_data_toggle, OutDataToggle);
    delegate_write!(write_out_data_toggle, OutDataToggle);
    delegate_read!(read_in_data_toggle, InDataToggle);
    delegate_write!(write_in_data_toggle, InDataToggle);
    delegate_read!(read_phy_pins_sense, PhyPinsSense);
    delegate_read!(read_phy_pins_drive, PhyPinsDrive);
    delegate_write!(write_phy_pins_drive, PhyPinsDrive);
    delegate_read!(read_phy_config, PhyConfig);
    delegate_write!(write_phy_config, PhyConfig);
    delegate_write!(write_wake_control, WakeControl);
    delegate_read!(read_wake_events, WakeEvents);
    delegate_write!(write_fifo_ctrl, FifoCtrl);
    delegate_read!(read_count_out, CountOut);
    delegate_write!(write_count_out, CountOut);
    delegate_read!(read_count_in, CountIn);
    delegate_write!(write_count_in, CountIn);
    delegate_read!(read_count_nodata_in, CountNodataIn);
    delegate_write!(write_count_nodata_in, CountNodataIn);
    delegate_read!(read_count_errors, CountErrors);
    delegate_write!(write_count_errors, CountErrors);

    fn read_buffer(&mut self, index: usize) -> caliptra_emu_types::RvData {
        let mut state = self.state.lock().unwrap();
        state.generated.read_buffer(index)
    }
    fn write_buffer(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        let mut state = self.state.lock().unwrap();
        state.generated.write_buffer(val, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use registers_generated::usbdev::bits::Usbctrl;
    use tock_registers::interfaces::Writeable;

    const USBDEV_BASE: u32 = registers_generated::usbdev::USBDEV_ADDR;
    const USBCTRL_OFFSET: u32 = 0x10;
    const EP_OUT_ENABLE_OFFSET: u32 = 0x14;
    const EP_IN_ENABLE_OFFSET: u32 = 0x18;
    const BUFFER_OFFSET: u32 = 0x800;

    fn setup() -> (AutoRootBus, UsbHostController) {
        let periph = UsbDevPeriph::new();
        let host = periph.host_controller();
        let bus = AutoRootBus::new(
            vec![],
            None,
            Some(Box::new(periph)),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        (bus, host)
    }

    #[test]
    fn test_register_read_write_usbctrl() {
        let (mut bus, _host) = setup();

        let val = bus
            .read(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET)
            .unwrap();
        assert_eq!(val, 0);

        let reg = caliptra_emu_bus::ReadWriteRegister::<u32, Usbctrl::Register>::new(0);
        reg.reg
            .write(Usbctrl::Enable::SET + Usbctrl::DeviceAddress.val(0x42));
        let write_val = reg.reg.get();

        bus.write(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET, write_val)
            .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET)
            .unwrap();
        assert_eq!(readback, write_val);
    }

    #[test]
    fn test_register_read_write_ep_enables() {
        let (mut bus, _host) = setup();

        bus.write(RvSize::Word, USBDEV_BASE + EP_OUT_ENABLE_OFFSET, 0xFFF)
            .unwrap();
        let val = bus
            .read(RvSize::Word, USBDEV_BASE + EP_OUT_ENABLE_OFFSET)
            .unwrap();
        assert_eq!(val, 0xFFF);

        bus.write(RvSize::Word, USBDEV_BASE + EP_IN_ENABLE_OFFSET, 0x0A5)
            .unwrap();
        let val = bus
            .read(RvSize::Word, USBDEV_BASE + EP_IN_ENABLE_OFFSET)
            .unwrap();
        assert_eq!(val, 0x0A5);
    }

    #[test]
    fn test_buffer_read_write() {
        let (mut bus, _host) = setup();

        for i in 0..16u32 {
            let addr = USBDEV_BASE + BUFFER_OFFSET + i * 4;
            bus.write(RvSize::Word, addr, 0xDEAD_0000 + i).unwrap();
        }
        for i in 0..16u32 {
            let addr = USBDEV_BASE + BUFFER_OFFSET + i * 4;
            let val = bus.read(RvSize::Word, addr).unwrap();
            assert_eq!(val, 0xDEAD_0000 + i);
        }
    }

    #[test]
    fn test_device_enabled_polling() {
        let (mut bus, host) = setup();

        assert!(!host.device_enabled());

        bus.write(
            RvSize::Word,
            USBDEV_BASE + USBCTRL_OFFSET,
            Usbctrl::Enable::SET.value,
        )
        .unwrap();
        assert!(host.device_enabled());

        bus.write(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET, 0)
            .unwrap();
        assert!(!host.device_enabled());
    }
}
