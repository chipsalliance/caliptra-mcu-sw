// Licensed under the Apache-2.0 license

//! Examplar `usbdev` implementation of [`UsbDeviceDriver`] for OCP Recovery.

#![cfg_attr(target_arch = "riscv32", no_std)]

use ocp::error::OcpError;
use ocp::protocol::RecoveryCommand;
use ocp::usb::descriptors::*;
use ocp::usb::driver::{RecoveryRequest, UsbDeviceDriver, UsbDriverError};
use ocp::usb::setup::{RequestType, SetupPacket, StandardRequest, SETUP_PACKET_LEN};
use registers_generated::usbdev;
use registers_generated::usbdev::bits::*;
use romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::LocalRegisterCopy;
use zerocopy::{FromBytes, IntoBytes};

type RxEntry = LocalRegisterCopy<u32, Rxfifo::Register>;

const MAX_PKT: usize = 64;
const BUF_SETUP: u32 = 0;
const BUF_OUT_START: u32 = 1;
const BUF_OUT_END: u32 = 2;
const BUF_IN: u32 = 3;

const MAX_WRITE_TRANSFER: usize = 1024;

/// Buffer word offset in the SRAM window: buffer N starts at word index N*16.
const fn buf_word_base(buf_id: u32) -> usize {
    (buf_id as usize) * 16
}

pub struct ExamplarUsbDriver {
    regs: StaticRef<usbdev::regs::Usbdev>,
    out_buf: [u8; MAX_WRITE_TRANSFER],
    /// Set to `Some(wLength)` after `recv` returns a `Read` request.
    /// Consumed by `send` / `stall_endpoint` to complete the transfer.
    pending_read_len: Option<u16>,
}

impl ExamplarUsbDriver {
    pub const fn new(regs: StaticRef<usbdev::regs::Usbdev>) -> Self {
        Self {
            regs,
            out_buf: [0u8; MAX_WRITE_TRANSFER],
            pending_read_len: None,
        }
    }

    fn get_in_buf(&self) -> u32 {
        let buf = BUF_IN;

        // Zeroize the buffer before sending data out on it.
        let base = buf_word_base(buf);
        for i in 0..16 {
            self.regs.buffer[base + i].set(0);
        }
        buf
    }

    fn read_setup_packet(&self, buf_id: u32) -> SetupPacket {
        let base = buf_word_base(buf_id);
        let w0 = self.regs.buffer[base].get();
        let w1 = self.regs.buffer[base + 1].get();
        let mut raw_bytes = [0u8; SETUP_PACKET_LEN];
        raw_bytes[..4].copy_from_slice(&w0.to_le_bytes());
        raw_bytes[4..].copy_from_slice(&w1.to_le_bytes());
        SetupPacket::read_from_bytes(&raw_bytes).unwrap()
    }

    fn write_buffer(&self, buf_id: u32, data: &[u8]) {
        let base = buf_word_base(buf_id);
        let mut i = 0;
        while i < data.len() {
            let end = core::cmp::min(i + 4, data.len());
            let mut word_bytes = [0u8; 4];
            word_bytes[..end - i].copy_from_slice(&data[i..end]);
            self.regs.buffer[base + i / 4].set(u32::from_le_bytes(word_bytes));
            i += 4;
        }
    }

    fn read_buffer_into(&mut self, buf_id: u32, size: usize, offset: usize) {
        let base = buf_word_base(buf_id);
        let mut i = 0;
        while i < size {
            let word = self.regs.buffer[base + i / 4].get();
            let bytes = word.to_le_bytes();
            let chunk = core::cmp::min(4, size - i);
            self.out_buf[offset + i..offset + i + chunk].copy_from_slice(&bytes[..chunk]);
            i += 4;
        }
    }

    fn poll_rx(&self) -> Option<RxEntry> {
        if !self.regs.intr_state.is_set(IntrState::PktReceived) {
            return None;
        }
        Some(self.regs.rxfifo.extract())
    }

    fn wait_rx(&self) -> RxEntry {
        loop {
            if let Some(rx) = self.poll_rx() {
                return rx;
            }
        }
    }

    fn rearm_setup(&self, buf_id: u32) {
        self.regs.avsetupbuffer.set(buf_id);
    }

    fn rearm_out(&self, buf_id: u32) {
        self.regs.avoutbuffer.set(buf_id);
        self.regs.rxenable_out.set(0x001);
    }

    /// Send data over EP0 IN, segmented into MaxPacketSize chunks.
    ///
    /// `expected` is the host's `wLength` for this control transfer.
    /// Per USB 2.0 §5.5.3, the data stage is complete when the host
    /// has received exactly `wLength` bytes OR the device sends a
    /// short/zero-length packet.  A ZLP is therefore only required
    /// when `data.len() < expected` and the last packet is full-size.
    fn send_in(&self, data: &[u8], expected: usize) -> Result<(), UsbDriverError> {
        for chunk in data.chunks(MAX_PKT) {
            let buf = self.get_in_buf();
            self.write_buffer(buf, chunk);

            self.regs.configin_0[0]
                .write(Configin0::Buffer0.val(buf) + Configin0::Size0.val(chunk.len() as u32));
            self.regs.configin_0[0].write(
                Configin0::Buffer0.val(buf)
                    + Configin0::Size0.val(chunk.len() as u32)
                    + Configin0::Rdy0::SET,
            );

            self.wait_in_sent();
        }
        if data.len() < expected && data.len() % MAX_PKT == 0 {
            self.send_zlp_in()?;
        }
        Ok(())
    }

    fn send_zlp_in(&self) -> Result<(), UsbDriverError> {
        let buf = self.get_in_buf();
        self.regs.configin_0[0].write(Configin0::Buffer0.val(buf) + Configin0::Size0.val(0));
        self.regs.configin_0[0]
            .write(Configin0::Buffer0.val(buf) + Configin0::Size0.val(0) + Configin0::Rdy0::SET);
        self.wait_in_sent();
        Ok(())
    }

    fn wait_in_sent(&self) {
        while !self.regs.in_sent.is_set(InSent::Sent0) {}
        self.regs.in_sent.set(InSent::Sent0::SET.value);
    }

    fn recv_zlp_out(&self) -> Result<(), UsbDriverError> {
        self.regs.avoutbuffer.set(BUF_OUT_START);
        self.regs.rxenable_out.set(0x001);
        loop {
            let rx = self.wait_rx();
            let buf_id = rx.read(Rxfifo::Buffer);
            if !rx.is_set(Rxfifo::Setup) && rx.read(Rxfifo::Size) == 0 {
                self.rearm_out(buf_id);
                return Ok(());
            }
            if rx.is_set(Rxfifo::Setup) {
                self.rearm_setup(buf_id);
            } else {
                self.rearm_out(buf_id);
            }
        }
    }

    fn stall_ep0(&self) {
        self.regs.in_stall.set(InStall::Endpoint0::SET.value);
        self.regs.out_stall.set(OutStall::Endpoint0::SET.value);
    }

    fn handle_standard_setup_request(
        &mut self,
        setup: &SetupPacket,
    ) -> Result<EnumAction, UsbDriverError> {
        let std_req = match setup.standard_request() {
            Some(r) => r,
            None => {
                self.stall_ep0();
                return Ok(EnumAction::Continue);
            }
        };

        match std_req {
            StandardRequest::GetDescriptor => self.handle_get_descriptor(setup),
            StandardRequest::SetAddress => {
                self.send_zlp_in()?;
                let addr = setup.w_value[0] & 0x7F;
                self.regs
                    .usbctrl
                    .write(Usbctrl::Enable::SET + Usbctrl::DeviceAddress.val(addr as u32));
                Ok(EnumAction::Continue)
            }
            StandardRequest::SetConfiguration => {
                self.send_zlp_in()?;
                Ok(EnumAction::Configured)
            }
            StandardRequest::GetStatus => {
                self.send_in(&[0x01, 0x00], setup.data_length().into())?;
                self.recv_zlp_out()?;
                Ok(EnumAction::Continue)
            }
            _ => {
                self.stall_ep0();
                Ok(EnumAction::Continue)
            }
        }
    }

    fn handle_get_descriptor(&mut self, setup: &SetupPacket) -> Result<EnumAction, UsbDriverError> {
        let desc_type = setup.descriptor_type();
        let w_length = setup.data_length().into();

        match desc_type {
            Some(DescriptorType::Device) => {
                let desc = DeviceDescriptor::ocp(0x0200, 0x1209, 0x0001, 0x0100, 0, 0, 0);
                let bytes = desc.as_bytes();
                let len = core::cmp::min(bytes.len(), w_length);
                self.send_in(&bytes[..len], w_length)?;
                self.recv_zlp_out()?;
            }
            Some(DescriptorType::Configuration) => {
                let tree = ConfigurationTree::ocp(
                    BmAttributes::new(true, false),
                    MaxPower2mA(50),
                    None,
                    MAX_WRITE_TRANSFER as u16,
                    MAX_WRITE_TRANSFER as u16,
                );
                let bytes = tree.as_bytes();
                let len = core::cmp::min(bytes.len(), w_length);
                self.send_in(&bytes[..len], w_length)?;
                self.recv_zlp_out()?;
            }
            Some(DescriptorType::String) => match setup.descriptor_index() {
                0 => {
                    let desc = StringDescriptorZero::ocp();
                    let bytes = desc.as_bytes();
                    let len = core::cmp::min(bytes.len(), w_length);
                    self.send_in(&bytes[..len], w_length)?;
                    self.recv_zlp_out()?;
                }
                OCP_INTERFACE_STRING_INDEX => {
                    let desc = OcpInterfaceStringDescriptor::ocp();
                    let bytes = desc.as_bytes();
                    let len = core::cmp::min(bytes.len(), w_length);
                    self.send_in(&bytes[..len], w_length)?;
                    self.recv_zlp_out()?;
                }
                _ => self.stall_ep0(),
            },
            Some(DescriptorType::DeviceQualifier) => self.stall_ep0(),
            _ => self.stall_ep0(),
        }

        Ok(EnumAction::Continue)
    }
}

enum EnumAction {
    Continue,
    Configured,
}

impl UsbDeviceDriver for ExamplarUsbDriver {
    fn init(&mut self) -> Result<(), UsbDriverError> {
        // Hardware setup: enable EP0, supply buffers, assert pull-up
        self.regs.ep_out_enable.set(0x001);
        self.regs.ep_in_enable.set(0x001);
        self.regs.rxenable_setup.set(0x001);
        self.regs.rxenable_out.set(0x001);
        self.regs.avsetupbuffer.set(BUF_SETUP);
        self.regs.avoutbuffer.set(BUF_OUT_START);
        self.regs.avoutbuffer.set(BUF_OUT_END);
        self.regs.usbctrl.write(Usbctrl::Enable::SET);

        // Wait for the host-initiated bus reset before beginning enumeration.
        while !self.regs.intr_state.is_set(IntrState::LinkReset) {}
        self.regs.intr_state.set(IntrState::LinkReset::SET.value);

        // Enumeration loop: handle standard requests until SET_CONFIGURATION
        loop {
            let rx = self.wait_rx();
            let buf_id = rx.read(Rxfifo::Buffer);
            if !rx.is_set(Rxfifo::Setup) {
                self.rearm_out(buf_id);
                continue;
            }
            let setup = self.read_setup_packet(buf_id);
            self.rearm_setup(buf_id);

            match self.handle_standard_setup_request(&setup)? {
                EnumAction::Continue => {}
                EnumAction::Configured => return Ok(()),
            }
        }
    }

    fn recv(&mut self) -> Result<(RecoveryCommand, RecoveryRequest<'_>), UsbDriverError> {
        if self.pending_read_len.is_some() {
            return Err(UsbDriverError::SendRequired);
        }

        let rx = match self.poll_rx() {
            Some(rx) => rx,
            None => return Err(UsbDriverError::NoPendingCommand),
        };
        let buf_id = rx.read(Rxfifo::Buffer);

        if !rx.is_set(Rxfifo::Setup) {
            self.rearm_out(buf_id);
            return Err(UsbDriverError::NoPendingCommand);
        }

        let setup = self.read_setup_packet(buf_id);
        self.rearm_setup(buf_id);

        // Handle non-OCP requests internally (e.g. post-enumeration standard requests)
        let command = match setup.ocp_recovery_command() {
            Some(cmd) => cmd,
            None => {
                if setup.bm_request_type.request_type() == RequestType::Standard {
                    // Drop the configuration value, as we've already entered the configured state.
                    let _ = self.handle_standard_setup_request(&setup)?;
                } else {
                    self.stall_ep0();
                }
                return Err(UsbDriverError::NoPendingCommand);
            }
        };

        if setup.is_write() {
            let w_length = setup.data_length().into();
            if w_length == 0 {
                self.send_zlp_in()?;
                return Ok((command, RecoveryRequest::Write { data: &[] }));
            }
            if w_length > MAX_WRITE_TRANSFER {
                self.stall_ep0();
                return Err(UsbDriverError::TransferTooLarge);
            }

            // Read OUT data packets into internal buffer
            let mut total = 0;
            while total < w_length {
                let out_rx = self.wait_rx();
                let out_buf = out_rx.read(Rxfifo::Buffer);
                if out_rx.is_set(Rxfifo::Setup) {
                    self.rearm_setup(out_buf);
                    return Err(UsbDriverError::HardwareError);
                }
                let sz = out_rx.read(Rxfifo::Size) as usize;
                self.read_buffer_into(out_buf, sz, total);
                self.rearm_out(out_buf);
                total += sz;
            }
            // IN status ZLP completes the write transfer
            self.send_zlp_in()?;

            Ok((
                command,
                RecoveryRequest::Write {
                    data: &self.out_buf[..total],
                },
            ))
        } else {
            let w_length = setup.data_length();
            self.pending_read_len = Some(w_length);
            Ok((command, RecoveryRequest::Read { len: w_length }))
        }
    }

    fn send(
        &mut self,
        populate_buffer: &mut dyn FnMut(&mut [u8]) -> Result<usize, OcpError>,
    ) -> Result<(), UsbDriverError> {
        let expected: usize = self
            .pending_read_len
            .take()
            .ok_or(UsbDriverError::NoPendingRead)?
            .into();
        let len = populate_buffer(&mut self.out_buf).map_err(UsbDriverError::OcpError)?;
        if len > MAX_WRITE_TRANSFER {
            return Err(UsbDriverError::TransferTooLarge);
        }
        self.send_in(&self.out_buf[..len], expected)?;
        // self.send_out_buf(len, expected)?;
        self.recv_zlp_out()?;
        Ok(())
    }

    fn stall_endpoint(&mut self) -> Result<(), UsbDriverError> {
        self.pending_read_len = None;
        self.stall_ep0();
        Ok(())
    }
}
