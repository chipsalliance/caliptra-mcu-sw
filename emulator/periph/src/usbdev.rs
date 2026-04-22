// Licensed under the Apache-2.0 license

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tock_registers::interfaces::Readable;

use caliptra_emu_bus::ReadWriteRegister;
use caliptra_emu_cpu::Irq;
use emulator_registers_generated::usbdev::{UsbdevGenerated, UsbdevPeripheral};
use registers_generated::usbdev::bits::*;

const AV_SETUP_FIFO_DEPTH: usize = 4;
const AV_OUT_FIFO_DEPTH: usize = 8;
const RX_FIFO_DEPTH: usize = 8;

pub struct UsbDevState {
    pub(crate) generated: UsbdevGenerated,

    pub(crate) av_setup_fifo: VecDeque<u8>,
    pub(crate) av_out_fifo: VecDeque<u8>,
    pub(crate) rx_fifo: VecDeque<RxFifoEntry>,

    pub(crate) frame: u16,

    #[allow(dead_code)]
    pub(crate) out_data_toggle: u16,
    #[allow(dead_code)]
    pub(crate) in_data_toggle: u16,

    #[allow(dead_code)]
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

    /// Compute the current value of level-sensitive interrupt bits. These bits
    /// are tied to hardware conditions and re-assert automatically when the
    /// underlying condition is true, regardless of W1C writes.
    fn level_sensitive_bits(&mut self) -> u32 {
        let mut bits = 0u32;

        if !self.rx_fifo.is_empty() {
            bits |= IntrState::PktReceived::SET.value;
        }

        if self.generated.read_in_sent().reg.get() != 0 {
            bits |= IntrState::PktSent::SET.value;
        }

        let enabled = self.generated.read_usbctrl().reg.is_set(Usbctrl::Enable);

        if enabled && self.av_out_fifo.is_empty() {
            bits |= IntrState::AvOutEmpty::SET.value;
        }

        if enabled && self.av_setup_fifo.is_empty() {
            bits |= IntrState::AvSetupEmpty::SET.value;
        }

        if enabled && self.rx_fifo.len() >= RX_FIFO_DEPTH {
            bits |= IntrState::RxFull::SET.value;
        }

        bits
    }

    fn effective_intr_state(&mut self) -> u32 {
        self.hw_intr_state | self.level_sensitive_bits()
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
    irq: Option<Irq>,
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
            irq: None,
        }
    }

    pub fn new_with_irq(irq: Irq) -> Self {
        Self {
            state: Arc::new(Mutex::new(UsbDevState::new())),
            irq: Some(irq),
        }
    }

    fn update_irq(&mut self) {
        let mut state = self.state.lock().unwrap();
        let effective = state.effective_intr_state();
        let enable = state.generated.read_intr_enable().reg.get();
        if let Some(irq) = &self.irq {
            irq.set_level((effective & enable) != 0);
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
    pub(crate) state: Arc<Mutex<UsbDevState>>,
}

impl UsbHostController {
    /// Returns `true` if firmware has set the `enable` bit in the `usbctrl` register,
    /// indicating the device is initialized and ready to communicate.
    pub fn device_enabled(&self) -> bool {
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
        fn $method(&mut self) -> ReadWriteRegister<u32, $reg::Register> {
            let mut state = self.state.lock().unwrap();
            state.generated.$method()
        }
    };
}

macro_rules! delegate_write {
    ($method:ident, $reg:ident) => {
        fn $method(&mut self, val: ReadWriteRegister<u32, $reg::Register>) {
            let mut state = self.state.lock().unwrap();
            state.generated.$method(val);
        }
    };
}

impl UsbdevPeripheral for UsbDevPeriph {
    fn poll(&mut self) {
        self.update_irq();
    }
    fn warm_reset(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.hw_intr_state = 0;
        state.generated.warm_reset();
    }
    fn update_reset(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.hw_intr_state = 0;
        state.generated.update_reset();
    }

    fn read_intr_state(&mut self) -> ReadWriteRegister<u32, IntrState::Register> {
        let mut state = self.state.lock().unwrap();
        ReadWriteRegister::new(state.effective_intr_state())
    }

    fn write_intr_state(&mut self, val: ReadWriteRegister<u32, IntrState::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            state.hw_intr_state &= !val.reg.get();
        }
        self.update_irq();
    }

    delegate_read!(read_intr_enable, IntrEnable);

    fn write_intr_enable(&mut self, val: ReadWriteRegister<u32, IntrEnable::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            state.generated.write_intr_enable(val);
        }
        self.update_irq();
    }

    fn write_intr_test(&mut self, val: ReadWriteRegister<u32, IntrTest::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            state.hw_intr_state |= val.reg.get();
        }
        self.update_irq();
    }

    delegate_write!(write_alert_test, AlertTest);
    delegate_read!(read_usbctrl, Usbctrl);
    delegate_write!(write_usbctrl, Usbctrl);
    delegate_read!(read_ep_out_enable, EpOutEnable);
    delegate_write!(write_ep_out_enable, EpOutEnable);
    delegate_read!(read_ep_in_enable, EpInEnable);
    delegate_write!(write_ep_in_enable, EpInEnable);

    fn read_usbstat(&mut self) -> ReadWriteRegister<u32, Usbstat::Register> {
        let state = self.state.lock().unwrap();
        let val = Usbstat::Frame.val(state.frame as u32)
            + Usbstat::AvOutDepth.val(state.av_out_fifo.len() as u32)
            + Usbstat::AvSetupDepth.val(state.av_setup_fifo.len() as u32)
            + Usbstat::AvOutFull.val(u32::from(state.av_out_fifo.len() >= AV_OUT_FIFO_DEPTH))
            + Usbstat::RxDepth.val(state.rx_fifo.len() as u32)
            + Usbstat::AvSetupFull.val(u32::from(state.av_setup_fifo.len() >= AV_SETUP_FIFO_DEPTH))
            + Usbstat::RxEmpty.val(u32::from(state.rx_fifo.is_empty()));
        ReadWriteRegister::new(val.value)
    }

    fn write_avoutbuffer(&mut self, val: ReadWriteRegister<u32, Avoutbuffer::Register>) {
        let mut state = self.state.lock().unwrap();
        let buffer_id = val.reg.read(Avoutbuffer::Buffer) as u8;
        if state.av_out_fifo.len() >= AV_OUT_FIFO_DEPTH {
            state.hw_intr_state |= IntrState::AvOverflow::SET.value;
        } else {
            state.av_out_fifo.push_back(buffer_id);
        }
    }

    fn write_avsetupbuffer(&mut self, val: ReadWriteRegister<u32, Avsetupbuffer::Register>) {
        let mut state = self.state.lock().unwrap();
        let buffer_id = val.reg.read(Avsetupbuffer::Buffer) as u8;
        if state.av_setup_fifo.len() >= AV_SETUP_FIFO_DEPTH {
            state.hw_intr_state |= IntrState::AvOverflow::SET.value;
        } else {
            state.av_setup_fifo.push_back(buffer_id);
        }
    }

    fn read_rxfifo(&mut self) -> ReadWriteRegister<u32, Rxfifo::Register> {
        let mut state = self.state.lock().unwrap();
        let val = match state.rx_fifo.pop_front() {
            Some(entry) => {
                (Rxfifo::Buffer.val(entry.buffer as u32)
                    + Rxfifo::Size.val(entry.size as u32)
                    + Rxfifo::Setup.val(u32::from(entry.setup))
                    + Rxfifo::Ep.val(entry.ep as u32))
                .value
            }
            None => 0,
        };
        ReadWriteRegister::new(val)
    }
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

    fn read_configin_0(&mut self, index: usize) -> ReadWriteRegister<u32, Configin0::Register> {
        let mut state = self.state.lock().unwrap();
        state.generated.read_configin_0(index)
    }
    fn write_configin_0(&mut self, val: ReadWriteRegister<u32, Configin0::Register>, index: usize) {
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

    fn write_fifo_ctrl(&mut self, val: ReadWriteRegister<u32, FifoCtrl::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            if val.reg.is_set(FifoCtrl::AvoutRst) {
                state.av_out_fifo.clear();
            }
            if val.reg.is_set(FifoCtrl::AvsetupRst) {
                state.av_setup_fifo.clear();
            }
            if val.reg.is_set(FifoCtrl::RxRst) {
                state.rx_fifo.clear();
            }
        }
        self.update_irq();
    }

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
    use tock_registers::interfaces::Writeable;

    const USBDEV_BASE: u32 = registers_generated::usbdev::USBDEV_ADDR;
    const INTR_STATE_OFFSET: u32 = 0x00;
    const INTR_ENABLE_OFFSET: u32 = 0x04;
    const INTR_TEST_OFFSET: u32 = 0x08;
    const USBCTRL_OFFSET: u32 = 0x10;
    const EP_OUT_ENABLE_OFFSET: u32 = 0x14;
    const EP_IN_ENABLE_OFFSET: u32 = 0x18;
    const USBSTAT_OFFSET: u32 = 0x1c;
    const AVOUTBUFFER_OFFSET: u32 = 0x20;
    const AVSETUPBUFFER_OFFSET: u32 = 0x24;
    const RXFIFO_OFFSET: u32 = 0x28;
    const FIFO_CTRL_OFFSET: u32 = 0x98;
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

        let reg = ReadWriteRegister::<u32, Usbctrl::Register>::new(0);
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

    #[test]
    fn test_av_setup_fifo_push_and_usbstat() {
        let (mut bus, _host) = setup();

        for i in 0..AV_SETUP_FIFO_DEPTH as u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, i)
                .unwrap();
        }

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(
            stat_reg.reg.read(Usbstat::AvSetupDepth),
            AV_SETUP_FIFO_DEPTH as u32
        );
        assert!(stat_reg.reg.is_set(Usbstat::AvSetupFull));
    }

    #[test]
    fn test_av_out_fifo_push_and_usbstat() {
        let (mut bus, _host) = setup();

        for i in 0..AV_OUT_FIFO_DEPTH as u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, i)
                .unwrap();
        }

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(
            stat_reg.reg.read(Usbstat::AvOutDepth),
            AV_OUT_FIFO_DEPTH as u32
        );
        assert!(stat_reg.reg.is_set(Usbstat::AvOutFull));
    }

    #[test]
    fn test_av_setup_fifo_overflow_sets_interrupt() {
        let (mut bus, host) = setup();

        // Fill the FIFO to capacity, then write one more
        for i in 0..=AV_SETUP_FIFO_DEPTH as u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, i)
                .unwrap();
        }

        // Depth should not exceed capacity (overflow write was discarded)
        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(
            stat_reg.reg.read(Usbstat::AvSetupDepth),
            AV_SETUP_FIFO_DEPTH as u32
        );

        let hw_intr = host.state.lock().unwrap().hw_intr_state;
        assert_ne!(hw_intr & IntrState::AvOverflow::SET.value, 0);
    }

    #[test]
    fn test_av_out_fifo_overflow_sets_interrupt() {
        let (mut bus, host) = setup();

        for i in 0..=AV_OUT_FIFO_DEPTH as u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, i)
                .unwrap();
        }

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(
            stat_reg.reg.read(Usbstat::AvOutDepth),
            AV_OUT_FIFO_DEPTH as u32
        );

        let hw_intr = host.state.lock().unwrap().hw_intr_state;
        assert_ne!(hw_intr & IntrState::AvOverflow::SET.value, 0);
    }

    #[test]
    fn test_rx_fifo_pop() {
        let (mut bus, host) = setup();

        {
            let mut state = host.state.lock().unwrap();
            state.rx_fifo.push_back(RxFifoEntry {
                buffer: 3,
                size: 64,
                setup: true,
                ep: 0,
            });
            state.rx_fifo.push_back(RxFifoEntry {
                buffer: 7,
                size: 8,
                setup: false,
                ep: 2,
            });
        }

        let val1 = bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        let reg1 = ReadWriteRegister::<u32, Rxfifo::Register>::new(val1);
        assert_eq!(reg1.reg.read(Rxfifo::Buffer), 3);
        assert_eq!(reg1.reg.read(Rxfifo::Size), 64);
        assert!(reg1.reg.is_set(Rxfifo::Setup));
        assert_eq!(reg1.reg.read(Rxfifo::Ep), 0);

        let val2 = bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        let reg2 = ReadWriteRegister::<u32, Rxfifo::Register>::new(val2);
        assert_eq!(reg2.reg.read(Rxfifo::Buffer), 7);
        assert_eq!(reg2.reg.read(Rxfifo::Size), 8);
        assert!(!reg2.reg.is_set(Rxfifo::Setup));
        assert_eq!(reg2.reg.read(Rxfifo::Ep), 2);

        let val3 = bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        assert_eq!(val3, 0);
    }

    #[test]
    fn test_usbstat_rx_empty_when_fifo_empty() {
        let (mut bus, _host) = setup();

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert!(stat_reg.reg.is_set(Usbstat::RxEmpty));
        assert_eq!(stat_reg.reg.read(Usbstat::RxDepth), 0);
    }

    #[test]
    fn test_fifo_ctrl_reset() {
        let (mut bus, host) = setup();

        for i in 0..3u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, i)
                .unwrap();
        }
        for i in 0..5u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, i)
                .unwrap();
        }
        {
            let mut state = host.state.lock().unwrap();
            state.rx_fifo.push_back(RxFifoEntry {
                buffer: 1,
                size: 8,
                setup: false,
                ep: 0,
            });
        }

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(stat_reg.reg.read(Usbstat::AvSetupDepth), 3);
        assert_eq!(stat_reg.reg.read(Usbstat::AvOutDepth), 5);
        assert_eq!(stat_reg.reg.read(Usbstat::RxDepth), 1);

        bus.write(
            RvSize::Word,
            USBDEV_BASE + FIFO_CTRL_OFFSET,
            (FifoCtrl::AvsetupRst::SET + FifoCtrl::AvoutRst::SET + FifoCtrl::RxRst::SET).value,
        )
        .unwrap();

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(stat_reg.reg.read(Usbstat::AvSetupDepth), 0);
        assert_eq!(stat_reg.reg.read(Usbstat::AvOutDepth), 0);
        assert_eq!(stat_reg.reg.read(Usbstat::RxDepth), 0);
        assert!(stat_reg.reg.is_set(Usbstat::RxEmpty));
    }

    // --- Phase 3: Interrupt logic tests ---

    fn read_intr_state(bus: &mut AutoRootBus) -> u32 {
        bus.read(RvSize::Word, USBDEV_BASE + INTR_STATE_OFFSET)
            .unwrap()
    }

    #[test]
    fn test_intr_state_level_sensitive_av_empty() {
        let (mut bus, _host) = setup();

        // Device not enabled => av_out_empty and av_setup_empty should NOT be set
        assert_eq!(read_intr_state(&mut bus), 0);

        // Enable the device
        bus.write(
            RvSize::Word,
            USBDEV_BASE + USBCTRL_OFFSET,
            Usbctrl::Enable::SET.value,
        )
        .unwrap();

        // Now with device enabled and FIFOs empty, both av_*_empty should fire
        let intr = read_intr_state(&mut bus);
        assert_ne!(intr & IntrState::AvOutEmpty::SET.value, 0);
        assert_ne!(intr & IntrState::AvSetupEmpty::SET.value, 0);

        // Push a buffer into each FIFO — the empty bits should clear
        bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, 0)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, 0)
            .unwrap();

        let intr = read_intr_state(&mut bus);
        assert_eq!(intr & IntrState::AvOutEmpty::SET.value, 0);
        assert_eq!(intr & IntrState::AvSetupEmpty::SET.value, 0);
    }

    #[test]
    fn test_intr_state_level_sensitive_pkt_received() {
        let (mut bus, host) = setup();

        assert_eq!(
            read_intr_state(&mut bus) & IntrState::PktReceived::SET.value,
            0
        );

        {
            let mut state = host.state.lock().unwrap();
            state.rx_fifo.push_back(RxFifoEntry {
                buffer: 0,
                size: 8,
                setup: false,
                ep: 0,
            });
        }

        assert_ne!(
            read_intr_state(&mut bus) & IntrState::PktReceived::SET.value,
            0
        );

        // Pop the entry — pkt_received should clear
        bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        assert_eq!(
            read_intr_state(&mut bus) & IntrState::PktReceived::SET.value,
            0
        );
    }

    #[test]
    fn test_intr_state_w1c_edge_triggered() {
        let (mut bus, _host) = setup();

        // Cause an av_overflow (edge-triggered)
        for i in 0..=AV_OUT_FIFO_DEPTH as u32 {
            bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, i)
                .unwrap();
        }
        assert_ne!(
            read_intr_state(&mut bus) & IntrState::AvOverflow::SET.value,
            0
        );

        // W1C: write 1 to clear av_overflow
        bus.write(
            RvSize::Word,
            USBDEV_BASE + INTR_STATE_OFFSET,
            IntrState::AvOverflow::SET.value,
        )
        .unwrap();

        assert_eq!(
            read_intr_state(&mut bus) & IntrState::AvOverflow::SET.value,
            0
        );
    }

    #[test]
    fn test_intr_state_w1c_does_not_clear_level_sensitive() {
        let (mut bus, host) = setup();

        // Push an RX entry so pkt_received is level-asserted
        {
            let mut state = host.state.lock().unwrap();
            state.rx_fifo.push_back(RxFifoEntry {
                buffer: 0,
                size: 8,
                setup: false,
                ep: 0,
            });
        }

        assert_ne!(
            read_intr_state(&mut bus) & IntrState::PktReceived::SET.value,
            0
        );

        // Try to W1C pkt_received — it should re-assert because the FIFO is still non-empty
        bus.write(
            RvSize::Word,
            USBDEV_BASE + INTR_STATE_OFFSET,
            IntrState::PktReceived::SET.value,
        )
        .unwrap();

        assert_ne!(
            read_intr_state(&mut bus) & IntrState::PktReceived::SET.value,
            0
        );
    }

    #[test]
    fn test_intr_test_force_sets_bits() {
        let (mut bus, _host) = setup();

        assert_eq!(read_intr_state(&mut bus) & IntrState::Frame::SET.value, 0);

        bus.write(
            RvSize::Word,
            USBDEV_BASE + INTR_TEST_OFFSET,
            IntrState::Frame::SET.value,
        )
        .unwrap();

        assert_ne!(read_intr_state(&mut bus) & IntrState::Frame::SET.value, 0);

        // W1C should clear it since Frame is edge-triggered
        bus.write(
            RvSize::Word,
            USBDEV_BASE + INTR_STATE_OFFSET,
            IntrState::Frame::SET.value,
        )
        .unwrap();
        assert_eq!(read_intr_state(&mut bus) & IntrState::Frame::SET.value, 0);
    }

    #[test]
    fn test_intr_enable_gating() {
        let (mut bus, _host) = setup();

        // Enable the device so av_out_empty fires
        bus.write(
            RvSize::Word,
            USBDEV_BASE + USBCTRL_OFFSET,
            Usbctrl::Enable::SET.value,
        )
        .unwrap();

        // intr_state should show av_out_empty
        assert_ne!(
            read_intr_state(&mut bus) & IntrState::AvOutEmpty::SET.value,
            0
        );

        // But intr_enable defaults to 0, so reading it should confirm
        let enable = bus
            .read(RvSize::Word, USBDEV_BASE + INTR_ENABLE_OFFSET)
            .unwrap();
        assert_eq!(enable, 0);

        // Enable the av_out_empty interrupt
        bus.write(
            RvSize::Word,
            USBDEV_BASE + INTR_ENABLE_OFFSET,
            IntrState::AvOutEmpty::SET.value,
        )
        .unwrap();
        let enable = bus
            .read(RvSize::Word, USBDEV_BASE + INTR_ENABLE_OFFSET)
            .unwrap();
        assert_eq!(enable, IntrState::AvOutEmpty::SET.value);
    }
}
