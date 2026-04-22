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
    pub(crate) in_sending: u16,

    pub(crate) hw_intr_state: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RxFifoEntry {
    pub buffer: u8,
    pub size: u8,
    pub setup: bool,
    pub ep: u8,
}

#[derive(Debug)]
pub enum UsbTransactionError {
    EndpointDisabled,
    Nak,
    Stall,
    NoBuffer,
    FifoFull,
    DataTooLong,
}

const MAX_PACKET_SIZE: usize = 64;
const WORDS_PER_BUFFER: usize = 16;

impl UsbDevState {
    fn new() -> Self {
        Self {
            generated: UsbdevGenerated::new(),
            av_setup_fifo: VecDeque::new(),
            av_out_fifo: VecDeque::new(),
            rx_fifo: VecDeque::new(),
            frame: 0,
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

    fn ep_bit(reg_val: u32, ep: u8) -> bool {
        reg_val & (1 << ep) != 0
    }

    fn write_data_to_buffer(&mut self, buffer_id: u8, data: &[u8]) {
        let base = usize::from(buffer_id) * WORDS_PER_BUFFER;
        for (i, chunk) in data.chunks(4).enumerate() {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            self.generated
                .write_buffer(u32::from_le_bytes(buf), base + i);
        }
    }

    fn read_data_from_buffer(&mut self, buffer_id: u8, size: usize) -> Vec<u8> {
        let base = usize::from(buffer_id) * WORDS_PER_BUFFER;
        let num_words = (size + 3) / 4;
        let mut data = Vec::with_capacity(num_words * 4);
        for i in 0..num_words {
            data.extend_from_slice(&self.generated.read_buffer(base + i).to_le_bytes());
        }
        data.truncate(size);
        data
    }

    pub(crate) fn do_host_setup(&mut self, ep: u8, data: &[u8]) -> Result<(), UsbTransactionError> {
        let ep_out = self.generated.read_ep_out_enable().reg.get();
        let rx_setup = self.generated.read_rxenable_setup().reg.get();
        if !Self::ep_bit(ep_out, ep) || !Self::ep_bit(rx_setup, ep) {
            return Err(UsbTransactionError::EndpointDisabled);
        }

        if self.rx_fifo.len() >= RX_FIFO_DEPTH {
            return Err(UsbTransactionError::FifoFull);
        }

        let buffer_id = self
            .av_setup_fifo
            .pop_front()
            .ok_or(UsbTransactionError::NoBuffer)?;

        if data.len() > MAX_PACKET_SIZE {
            return Err(UsbTransactionError::DataTooLong);
        }
        self.write_data_to_buffer(buffer_id, data);

        self.rx_fifo.push_back(RxFifoEntry {
            buffer: buffer_id,
            size: data.len() as u8,
            setup: true,
            ep,
        });

        // SETUP clears stall on both directions
        let out_stall = self.generated.read_out_stall().reg.get() & !(1 << ep);
        self.generated
            .write_out_stall(ReadWriteRegister::new(out_stall));
        let in_stall = self.generated.read_in_stall().reg.get() & !(1 << ep);
        self.generated
            .write_in_stall(ReadWriteRegister::new(in_stall));

        // Cancel any pending IN on this endpoint
        let configin = self.generated.read_configin_0(ep as usize);
        let raw = (configin.reg.get() & !Configin0::Rdy0::SET.value) | Configin0::Pend0::SET.value;
        self.generated
            .write_configin_0(ReadWriteRegister::new(raw), ep as usize);

        Ok(())
    }

    pub(crate) fn do_host_out(&mut self, ep: u8, data: &[u8]) -> Result<(), UsbTransactionError> {
        let ep_out = self.generated.read_ep_out_enable().reg.get();
        if !Self::ep_bit(ep_out, ep) {
            return Err(UsbTransactionError::EndpointDisabled);
        }

        let out_stall = self.generated.read_out_stall().reg.get();
        if Self::ep_bit(out_stall, ep) {
            return Err(UsbTransactionError::Stall);
        }

        let rxenable_out = self.generated.read_rxenable_out().reg.get();
        if !Self::ep_bit(rxenable_out, ep) {
            return Err(UsbTransactionError::Nak);
        }

        if self.rx_fifo.len() >= RX_FIFO_DEPTH {
            return Err(UsbTransactionError::FifoFull);
        }

        let buffer_id = self
            .av_out_fifo
            .pop_front()
            .ok_or(UsbTransactionError::NoBuffer)?;

        if data.len() > MAX_PACKET_SIZE {
            return Err(UsbTransactionError::DataTooLong);
        }
        self.write_data_to_buffer(buffer_id, data);

        self.rx_fifo.push_back(RxFifoEntry {
            buffer: buffer_id,
            size: data.len() as u8,
            setup: false,
            ep,
        });

        // If set_nak_out is set for this endpoint, clear rxenable_out
        let set_nak = self.generated.read_set_nak_out().reg.get();
        if Self::ep_bit(set_nak, ep) {
            let rxenable = rxenable_out & !(1 << ep);
            self.generated
                .write_rxenable_out(ReadWriteRegister::new(rxenable));
        }

        Ok(())
    }

    pub(crate) fn do_host_in(&mut self, ep: u8) -> Result<Vec<u8>, UsbTransactionError> {
        let ep_in = self.generated.read_ep_in_enable().reg.get();
        if !Self::ep_bit(ep_in, ep) {
            return Err(UsbTransactionError::EndpointDisabled);
        }

        let in_stall = self.generated.read_in_stall().reg.get();
        if Self::ep_bit(in_stall, ep) {
            return Err(UsbTransactionError::Stall);
        }

        let configin = self.generated.read_configin_0(ep as usize);
        if !configin.reg.is_set(Configin0::Rdy0) {
            return Err(UsbTransactionError::Nak);
        }

        let buffer_id = configin.reg.read(Configin0::Buffer0) as u8;
        let size = configin.reg.read(Configin0::Size0) as usize;
        let size = size.min(MAX_PACKET_SIZE);

        let data = self.read_data_from_buffer(buffer_id, size);

        // Clear rdy for this endpoint
        let raw = configin.reg.get() & !Configin0::Rdy0::SET.value;
        self.generated
            .write_configin_0(ReadWriteRegister::new(raw), ep as usize);

        let in_sent = self.generated.read_in_sent().reg.get() | (1 << ep);
        self.generated
            .write_in_sent(ReadWriteRegister::new(in_sent));

        Ok(data)
    }

    pub(crate) fn do_host_sof(&mut self, frame_number: u16) {
        self.frame = frame_number;
        self.hw_intr_state |= IntrState::Frame::SET.value;
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

    /// Simulate the host sending a SETUP packet to an endpoint.
    pub fn host_setup(&self, ep: u8, data: &[u8]) -> Result<(), UsbTransactionError> {
        let mut state = self.state.lock().unwrap();
        state.do_host_setup(ep, data)
    }

    /// Simulate the host sending an OUT packet to an endpoint.
    pub fn host_out(&self, ep: u8, data: &[u8]) -> Result<(), UsbTransactionError> {
        let mut state = self.state.lock().unwrap();
        state.do_host_out(ep, data)
    }

    /// Simulate the host performing an IN transaction on an endpoint.
    pub fn host_in(&self, ep: u8) -> Result<Vec<u8>, UsbTransactionError> {
        let mut state = self.state.lock().unwrap();
        state.do_host_in(ep)
    }

    /// Send a SOF token (advances frame counter).
    pub fn host_sof(&self, frame_number: u16) {
        let mut state = self.state.lock().unwrap();
        state.do_host_sof(frame_number);
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

    fn write_usbctrl(&mut self, val: ReadWriteRegister<u32, Usbctrl::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            state.generated.write_usbctrl(val);
        }
        self.update_irq();
    }
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
        {
            let mut state = self.state.lock().unwrap();
            let buffer_id = val.reg.read(Avoutbuffer::Buffer) as u8;
            if state.av_out_fifo.len() >= AV_OUT_FIFO_DEPTH {
                state.hw_intr_state |= IntrState::AvOverflow::SET.value;
            } else {
                state.av_out_fifo.push_back(buffer_id);
            }
        }
        self.update_irq();
    }

    fn write_avsetupbuffer(&mut self, val: ReadWriteRegister<u32, Avsetupbuffer::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            let buffer_id = val.reg.read(Avsetupbuffer::Buffer) as u8;
            if state.av_setup_fifo.len() >= AV_SETUP_FIFO_DEPTH {
                state.hw_intr_state |= IntrState::AvOverflow::SET.value;
            } else {
                state.av_setup_fifo.push_back(buffer_id);
            }
        }
        self.update_irq();
    }

    fn read_rxfifo(&mut self) -> ReadWriteRegister<u32, Rxfifo::Register> {
        let val;
        {
            let mut state = self.state.lock().unwrap();
            val = match state.rx_fifo.pop_front() {
                Some(entry) => {
                    (Rxfifo::Buffer.val(entry.buffer as u32)
                        + Rxfifo::Size.val(entry.size as u32)
                        + Rxfifo::Setup.val(u32::from(entry.setup))
                        + Rxfifo::Ep.val(entry.ep as u32))
                    .value
                }
                None => 0,
            };
        }
        self.update_irq();
        ReadWriteRegister::new(val)
    }
    delegate_read!(read_rxenable_setup, RxenableSetup);
    delegate_write!(write_rxenable_setup, RxenableSetup);
    delegate_read!(read_rxenable_out, RxenableOut);

    fn write_rxenable_out(&mut self, val: ReadWriteRegister<u32, RxenableOut::Register>) {
        let mut state = self.state.lock().unwrap();
        let preserve = val.reg.read(RxenableOut::Preserve);
        let written_out = val.reg.read(RxenableOut::Out);
        let current_out = state
            .generated
            .read_rxenable_out()
            .reg
            .read(RxenableOut::Out);
        let new_out = (current_out & preserve) | (written_out & !preserve);
        state
            .generated
            .write_rxenable_out(ReadWriteRegister::new(new_out));
    }
    delegate_read!(read_set_nak_out, SetNakOut);
    delegate_write!(write_set_nak_out, SetNakOut);
    delegate_read!(read_in_sent, InSent);

    fn write_in_sent(&mut self, val: ReadWriteRegister<u32, InSent::Register>) {
        {
            let mut state = self.state.lock().unwrap();
            let current = state.generated.read_in_sent().reg.get();
            state
                .generated
                .write_in_sent(ReadWriteRegister::new(current & !val.reg.get()));
        }
        self.update_irq();
    }
    delegate_read!(read_out_stall, OutStall);
    delegate_write!(write_out_stall, OutStall);
    delegate_read!(read_in_stall, InStall);
    delegate_write!(write_in_stall, InStall);

    fn read_configin_0(&mut self, index: usize) -> ReadWriteRegister<u32, Configin0::Register> {
        let mut state = self.state.lock().unwrap();
        let stored = state.generated.read_configin_0(index).reg.get();
        let sending_bit = if state.in_sending & (1 << index) != 0 {
            Configin0::Sending0::SET.value
        } else {
            0
        };
        ReadWriteRegister::new((stored & !Configin0::Sending0::SET.value) | sending_bit)
    }

    fn write_configin_0(&mut self, val: ReadWriteRegister<u32, Configin0::Register>, index: usize) {
        let mut state = self.state.lock().unwrap();
        let current = state.generated.read_configin_0(index).reg.get();

        // pend is W1C: writing 1 clears it
        let pend_clear = val.reg.get() & Configin0::Pend0::SET.value;
        // sending is read-only from software: preserve hardware value
        let sending = current & Configin0::Sending0::SET.value;

        let writable_mask = !(Configin0::Pend0::SET.value | Configin0::Sending0::SET.value);
        let new_val = (val.reg.get() & writable_mask)
            | ((current & Configin0::Pend0::SET.value) & !pend_clear)
            | sending;
        state
            .generated
            .write_configin_0(ReadWriteRegister::new(new_val), index);
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
    const RXENABLE_SETUP_OFFSET: u32 = 0x2c;
    const RXENABLE_OUT_OFFSET: u32 = 0x30;
    const SET_NAK_OUT_OFFSET: u32 = 0x34;
    const IN_SENT_OFFSET: u32 = 0x38;
    const OUT_STALL_OFFSET: u32 = 0x3c;
    const IN_STALL_OFFSET: u32 = 0x40;
    const CONFIGIN_BASE_OFFSET: u32 = 0x44;
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

    // --- Phase 4: Host transaction API tests ---

    /// Configure endpoint 0 for SETUP/OUT reception and IN transmission.
    fn enable_ep0(bus: &mut AutoRootBus) {
        bus.write(RvSize::Word, USBDEV_BASE + EP_OUT_ENABLE_OFFSET, 0x001)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + EP_IN_ENABLE_OFFSET, 0x001)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_SETUP_OFFSET, 0x001)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, 0x001)
            .unwrap();
    }

    #[test]
    fn test_host_setup_success() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Provide a setup buffer
        bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, 0)
            .unwrap();

        let setup_data = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00];
        host.host_setup(0, &setup_data).unwrap();

        // Read the RX FIFO entry
        let rxfifo = bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        let reg = ReadWriteRegister::<u32, Rxfifo::Register>::new(rxfifo);
        assert_eq!(reg.reg.read(Rxfifo::Buffer), 0);
        assert_eq!(reg.reg.read(Rxfifo::Size), 8);
        assert!(reg.reg.is_set(Rxfifo::Setup));
        assert_eq!(reg.reg.read(Rxfifo::Ep), 0);

        // Verify data in buffer 0
        for (i, &byte) in setup_data.iter().enumerate() {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            let word = bus
                .read(
                    RvSize::Word,
                    USBDEV_BASE + BUFFER_OFFSET + (word_idx as u32) * 4,
                )
                .unwrap();
            assert_eq!((word >> (byte_idx * 8)) as u8, byte);
        }
    }

    #[test]
    fn test_host_setup_no_buffer() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);
        // Don't provide any setup buffer
        let result = host.host_setup(0, &[0; 8]);
        assert!(matches!(result, Err(UsbTransactionError::NoBuffer)));
    }

    #[test]
    fn test_host_setup_endpoint_disabled() {
        let (_bus, host) = setup();
        // Don't enable any endpoints
        let result = host.host_setup(0, &[0; 8]);
        assert!(matches!(result, Err(UsbTransactionError::EndpointDisabled)));
    }

    #[test]
    fn test_host_setup_clears_stall() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Set stall on ep0
        bus.write(RvSize::Word, USBDEV_BASE + OUT_STALL_OFFSET, 0x001)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + IN_STALL_OFFSET, 0x001)
            .unwrap();

        bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, 0)
            .unwrap();
        host.host_setup(0, &[0; 8]).unwrap();

        // Stall should be cleared
        let out_stall = bus
            .read(RvSize::Word, USBDEV_BASE + OUT_STALL_OFFSET)
            .unwrap();
        let in_stall = bus
            .read(RvSize::Word, USBDEV_BASE + IN_STALL_OFFSET)
            .unwrap();
        assert_eq!(out_stall & 1, 0);
        assert_eq!(in_stall & 1, 0);
    }

    #[test]
    fn test_host_out_success() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, 1)
            .unwrap();

        let out_data = [0xDE, 0xAD, 0xBE, 0xEF];
        host.host_out(0, &out_data).unwrap();

        let rxfifo = bus.read(RvSize::Word, USBDEV_BASE + RXFIFO_OFFSET).unwrap();
        let reg = ReadWriteRegister::<u32, Rxfifo::Register>::new(rxfifo);
        assert_eq!(reg.reg.read(Rxfifo::Buffer), 1);
        assert_eq!(reg.reg.read(Rxfifo::Size), 4);
        assert!(!reg.reg.is_set(Rxfifo::Setup));
        assert_eq!(reg.reg.read(Rxfifo::Ep), 0);

        // Verify data in buffer 1 (word offset = 1 * 16 = 16)
        let word = bus
            .read(RvSize::Word, USBDEV_BASE + BUFFER_OFFSET + 16 * 4)
            .unwrap();
        assert_eq!(word, 0xEFBEADDE);
    }

    #[test]
    fn test_host_out_stall() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        bus.write(RvSize::Word, USBDEV_BASE + OUT_STALL_OFFSET, 0x001)
            .unwrap();

        let result = host.host_out(0, &[0; 4]);
        assert!(matches!(result, Err(UsbTransactionError::Stall)));
    }

    #[test]
    fn test_host_out_nak_rxenable_cleared() {
        let (mut bus, host) = setup();

        // Enable ep0 but clear rxenable_out
        bus.write(RvSize::Word, USBDEV_BASE + EP_OUT_ENABLE_OFFSET, 0x001)
            .unwrap();
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, 0x000)
            .unwrap();

        let result = host.host_out(0, &[0; 4]);
        assert!(matches!(result, Err(UsbTransactionError::Nak)));
    }

    #[test]
    fn test_host_out_set_nak_out_clears_rxenable() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Enable set_nak_out for ep0
        bus.write(RvSize::Word, USBDEV_BASE + SET_NAK_OUT_OFFSET, 0x001)
            .unwrap();

        bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, 0)
            .unwrap();
        host.host_out(0, &[0; 4]).unwrap();

        // rxenable_out should now be cleared for ep0
        let rxenable = bus
            .read(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET)
            .unwrap();
        assert_eq!(rxenable & 1, 0);

        // Next OUT should NAK
        bus.write(RvSize::Word, USBDEV_BASE + AVOUTBUFFER_OFFSET, 1)
            .unwrap();
        let result = host.host_out(0, &[0; 4]);
        assert!(matches!(result, Err(UsbTransactionError::Nak)));
    }

    #[test]
    fn test_host_in_success() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Write data into buffer 2
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05];
        let base_addr = USBDEV_BASE + BUFFER_OFFSET + 2 * 16 * 4;
        let word0 = 0x04030201u32;
        let word1 = 0x00000005u32;
        bus.write(RvSize::Word, base_addr, word0).unwrap();
        bus.write(RvSize::Word, base_addr + 4, word1).unwrap();

        // Configure configin[0]: buffer=2, size=5, rdy=1
        let configin_val =
            (Configin0::Buffer0.val(2) + Configin0::Size0.val(5) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();

        let data = host.host_in(0).unwrap();
        assert_eq!(data, payload);

        // configin[0].rdy should be cleared
        let configin_readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(configin_readback);
        assert!(!reg.reg.is_set(Configin0::Rdy0));

        // in_sent[0] should be set
        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_ne!(in_sent & 1, 0);
    }

    #[test]
    fn test_host_in_nak_not_ready() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // configin[0] defaults to 0 (rdy not set)
        let result = host.host_in(0);
        assert!(matches!(result, Err(UsbTransactionError::Nak)));
    }

    #[test]
    fn test_host_in_stall() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        bus.write(RvSize::Word, USBDEV_BASE + IN_STALL_OFFSET, 0x001)
            .unwrap();

        let result = host.host_in(0);
        assert!(matches!(result, Err(UsbTransactionError::Stall)));
    }

    #[test]
    fn test_host_sof_updates_frame() {
        let (mut bus, host) = setup();

        host.host_sof(42);

        let stat = bus
            .read(RvSize::Word, USBDEV_BASE + USBSTAT_OFFSET)
            .unwrap();
        let stat_reg = ReadWriteRegister::<u32, Usbstat::Register>::new(stat);
        assert_eq!(stat_reg.reg.read(Usbstat::Frame), 42);

        // Frame interrupt should be set
        let intr = read_intr_state(&mut bus);
        assert_ne!(intr & IntrState::Frame::SET.value, 0);
    }

    // --- Phase 5: USBCTRL register tests ---

    #[test]
    fn test_usbctrl_enable_triggers_av_empty_interrupts() {
        let (mut bus, _host) = setup();

        // With device disabled, av_empty interrupts should not fire
        let intr = read_intr_state(&mut bus);
        assert_eq!(intr & IntrState::AvOutEmpty::SET.value, 0);
        assert_eq!(intr & IntrState::AvSetupEmpty::SET.value, 0);

        // Enable the device — av_empty should now fire (FIFOs are empty)
        bus.write(
            RvSize::Word,
            USBDEV_BASE + USBCTRL_OFFSET,
            Usbctrl::Enable::SET.value,
        )
        .unwrap();

        let intr = read_intr_state(&mut bus);
        assert_ne!(intr & IntrState::AvOutEmpty::SET.value, 0);
        assert_ne!(intr & IntrState::AvSetupEmpty::SET.value, 0);

        // Disable the device — av_empty should stop
        bus.write(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET, 0)
            .unwrap();

        let intr = read_intr_state(&mut bus);
        assert_eq!(intr & IntrState::AvOutEmpty::SET.value, 0);
        assert_eq!(intr & IntrState::AvSetupEmpty::SET.value, 0);
    }

    #[test]
    fn test_usbctrl_device_address_preserved() {
        let (mut bus, _host) = setup();

        let val = (Usbctrl::Enable::SET + Usbctrl::DeviceAddress.val(0x2A)).value;
        bus.write(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET, val)
            .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + USBCTRL_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Usbctrl::Register>::new(readback);
        assert!(reg.reg.is_set(Usbctrl::Enable));
        assert_eq!(reg.reg.read(Usbctrl::DeviceAddress), 0x2A);
    }

    // --- Phase 6: Special register semantics tests ---

    #[test]
    fn test_in_sent_w1c() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Set up a successful IN so that in_sent[0] gets set by hardware
        let configin_val =
            (Configin0::Buffer0.val(0) + Configin0::Size0.val(1) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();
        host.host_in(0).unwrap();

        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_ne!(in_sent & 1, 0, "in_sent[0] should be set after IN ACK");

        // W1C: write 1 to bit 0 to clear it
        bus.write(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET, 1)
            .unwrap();

        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_eq!(in_sent & 1, 0, "in_sent[0] should be cleared by W1C");
    }

    #[test]
    fn test_in_sent_w1c_preserves_other_bits() {
        let (mut bus, host) = setup();

        // Enable ep0 and ep1 for IN
        bus.write(RvSize::Word, USBDEV_BASE + EP_IN_ENABLE_OFFSET, 0x003)
            .unwrap();

        // Trigger in_sent on both ep0 and ep1
        for ep in 0u32..2 {
            let offset = CONFIGIN_BASE_OFFSET + ep * 4;
            let configin_val =
                (Configin0::Buffer0.val(ep) + Configin0::Size0.val(1) + Configin0::Rdy0::SET).value;
            bus.write(RvSize::Word, USBDEV_BASE + offset, configin_val)
                .unwrap();
            host.host_in(ep as u8).unwrap();
        }

        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_ne!(in_sent & 0x3, 0);

        // Clear only ep0's bit
        bus.write(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET, 0x1)
            .unwrap();

        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_eq!(in_sent & 1, 0, "ep0 should be cleared");
        assert_ne!(in_sent & 2, 0, "ep1 should still be set");
    }

    #[test]
    fn test_in_sent_w1c_clears_pkt_sent_interrupt() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        let configin_val =
            (Configin0::Buffer0.val(0) + Configin0::Size0.val(1) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();
        host.host_in(0).unwrap();

        // pkt_sent should be asserted (level-sensitive, tied to in_sent != 0)
        let intr = read_intr_state(&mut bus);
        assert_ne!(intr & IntrState::PktSent::SET.value, 0);

        // Clear in_sent[0] via W1C
        bus.write(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET, 1)
            .unwrap();

        // pkt_sent should now be deasserted
        let intr = read_intr_state(&mut bus);
        assert_eq!(intr & IntrState::PktSent::SET.value, 0);
    }

    #[test]
    fn test_rxenable_out_preserve_masked_write() {
        let (mut bus, _host) = setup();

        // Set ep0 and ep1 enabled
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, 0x003)
            .unwrap();

        let val = bus
            .read(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET)
            .unwrap();
        assert_eq!(val & 0xFFF, 0x003);

        // Masked write: preserve ep0 (bit 0 of preserve field), set ep2, clear ep1
        // preserve = 0x001 (protect bit 0), out = 0x004 (set bit 2, clear bit 1)
        let masked_val = (RxenableOut::Preserve.val(0x001) + RxenableOut::Out.val(0x004)).value;
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, masked_val)
            .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET)
            .unwrap();
        // ep0 preserved (was 1, stays 1), ep1 not preserved (new val 0), ep2 not preserved (new val 1)
        assert_eq!(readback & 0xFFF, 0x005);
    }

    #[test]
    fn test_rxenable_out_preserve_all() {
        let (mut bus, _host) = setup();

        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, 0x00A)
            .unwrap();

        // Preserve all bits (preserve = 0xFFF)
        let masked_val = (RxenableOut::Preserve.val(0xFFF) + RxenableOut::Out.val(0x000)).value;
        bus.write(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET, masked_val)
            .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + RXENABLE_OUT_OFFSET)
            .unwrap();
        assert_eq!(readback & 0xFFF, 0x00A, "all bits should be preserved");
    }

    #[test]
    fn test_configin_pend_w1c() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Configure a ready IN buffer, then send a SETUP to cancel it (sets pend)
        let configin_val =
            (Configin0::Buffer0.val(0) + Configin0::Size0.val(4) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();

        bus.write(RvSize::Word, USBDEV_BASE + AVSETUPBUFFER_OFFSET, 1)
            .unwrap();
        host.host_setup(0, &[0; 8]).unwrap();

        // pend should be set, rdy cleared
        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(reg.reg.is_set(Configin0::Pend0), "pend should be set");
        assert!(!reg.reg.is_set(Configin0::Rdy0), "rdy should be cleared");

        // W1C: write 1 to pend to clear it
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            Configin0::Pend0::SET.value,
        )
        .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(
            !reg.reg.is_set(Configin0::Pend0),
            "pend should be cleared by W1C"
        );
    }

    #[test]
    fn test_configin_sending_read_only() {
        let (mut bus, host) = setup();

        // Directly set in_sending for ep0 via the shared state
        {
            let mut state = host.state.lock().unwrap();
            state.in_sending |= 1;
        }

        // Read configin[0] — sending bit should be set
        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(reg.reg.is_set(Configin0::Sending0));

        // Try to clear sending by writing 0 — it should remain set (read-only)
        bus.write(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET, 0)
            .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(
            reg.reg.is_set(Configin0::Sending0),
            "sending should be read-only from software"
        );
    }

    #[test]
    fn test_configin_rdy_writable() {
        let (mut bus, _host) = setup();

        // Write rdy=1 with buffer and size
        let configin_val =
            (Configin0::Buffer0.val(3) + Configin0::Size0.val(10) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(reg.reg.is_set(Configin0::Rdy0));
        assert_eq!(reg.reg.read(Configin0::Buffer0), 3);
        assert_eq!(reg.reg.read(Configin0::Size0), 10);

        // Clear rdy by writing without it
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            (Configin0::Buffer0.val(3) + Configin0::Size0.val(10)).value,
        )
        .unwrap();

        let readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(readback);
        assert!(!reg.reg.is_set(Configin0::Rdy0));
    }

    #[test]
    fn test_configin_end_to_end_in_transfer() {
        let (mut bus, host) = setup();
        enable_ep0(&mut bus);

        // Firmware writes a payload into buffer 5
        let payload = [0xCA, 0xFE, 0x7A, 0x8E, 0xDE, 0xAD];
        let buf5_base = USBDEV_BASE + BUFFER_OFFSET + 5 * 16 * 4;
        // Pack bytes into little-endian words
        bus.write(RvSize::Word, buf5_base, 0x8E7AFECA).unwrap();
        bus.write(RvSize::Word, buf5_base + 4, 0x0000ADDE).unwrap();

        // Firmware marks buffer 5 as ready on ep0: buffer=5, size=6, rdy=1
        let configin_val =
            (Configin0::Buffer0.val(5) + Configin0::Size0.val(6) + Configin0::Rdy0::SET).value;
        bus.write(
            RvSize::Word,
            USBDEV_BASE + CONFIGIN_BASE_OFFSET,
            configin_val,
        )
        .unwrap();

        // Host performs an IN transaction and retrieves the data
        let data = host.host_in(0).unwrap();
        assert_eq!(data, payload);

        // configin[0].rdy should be cleared, in_sent[0] should be set
        let configin_readback = bus
            .read(RvSize::Word, USBDEV_BASE + CONFIGIN_BASE_OFFSET)
            .unwrap();
        let reg = ReadWriteRegister::<u32, Configin0::Register>::new(configin_readback);
        assert!(!reg.reg.is_set(Configin0::Rdy0));

        let in_sent = bus
            .read(RvSize::Word, USBDEV_BASE + IN_SENT_OFFSET)
            .unwrap();
        assert_ne!(in_sent & 1, 0);
    }
}
