// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{MCTP_BASELINE_TRANSMISSION_UNIT, MCTP_HDR_SIZE};
use caliptra_mcu_i3c_driver::{
    core::{MAX_IBI_PAYLOAD_LEN, MAX_READ_WRITE_SIZE},
    hil::{I3CTarget, RxClient, TxClient},
};
use caliptra_mcu_romtime::println;
use core::cell::Cell;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;
use kernel::ErrorCode;

pub const MCTP_I3C_MAXBUF: usize = MAX_READ_WRITE_SIZE;

// Max MTU excludes the PEC byte appended by the transport binding layer.
pub const MCTP_I3C_MAXMTU: usize = MCTP_I3C_MAXBUF - 1;
pub const MCTP_I3C_MINMTU: usize = MCTP_HDR_SIZE + MCTP_BASELINE_TRANSMISSION_UNIT;
pub const MCTP_I3C_MIN_PACKET_SIZE: usize = MCTP_I3C_MINMTU + 1;

/// Mandatory Data Byte of the DSP0233 pending-read IBI.
pub const MCTP_PENDING_READ_MDB: u8 = 0xAE;

/// This trait contains the interface definition
/// for sending the MCTP packet through MCTP transport binding layer.
pub trait MCTPTransportBinding<'a> {
    /// Set the client that will be called when the packet is transmitted.
    fn set_tx_client(&self, client: &'a dyn TransportTxClient);

    /// Set the client that will be called when the packet is received.
    fn set_rx_client(&self, client: &'a dyn TransportRxClient);

    /// Set the buffer that will be used for receiving packets.
    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]);

    fn transmit(
        &self,
        tx_buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Enable/Disable the I3C target device
    fn enable(&self);
    fn disable(&self);

    /// Get the maximum transmission unit (MTU) size.
    fn get_mtu_size(&self) -> usize;

    /// Get hdr size of transport binding layer
    fn get_hdr_size(&self) -> usize;
}

pub trait TransportTxClient {
    /// Called when the packet has been transmitted.
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>);
}

pub trait TransportRxClient {
    /// Called when a complete MCTP packet is received and ready to be processed by the client.
    fn receive(&self, rx_buffer: &'static mut [u8], len: usize);

    /// Called when the I3C Controller has requested a private Write by addressing the target
    /// and the driver needs buffer to receive the data.
    fn write_expected(&self);
}

pub struct MCTPI3CBinding<'a> {
    /// Reference to the I3C Target device driver.
    i3c_target: &'a dyn I3CTarget<'a>,
    rx_client: OptionalCell<&'a dyn TransportRxClient>,
    tx_client: OptionalCell<&'a dyn TransportTxClient>,
    /// I3C Target device address needed for PEC calculation.
    device_address: Cell<u8>,
    /// Max Read length supported by the I3C target device.
    max_read_len: Cell<usize>,
    /// Max Write length supported by the I3C target device.
    max_write_len: Cell<usize>,
    /// Number of big-endian response-length bytes appended after the MDB in
    /// the pending-read IBI.
    pending_read_ibi_len_bytes: usize,
    /// Buffer to store the transmitted packet.
    tx_buffer: TakeCell<'static, [u8]>,
}

impl<'a> MCTPI3CBinding<'a> {
    pub fn new(i3c_target: &'a dyn I3CTarget<'a>) -> MCTPI3CBinding<'a> {
        MCTPI3CBinding {
            i3c_target,
            rx_client: OptionalCell::empty(),
            tx_client: OptionalCell::empty(),
            device_address: Cell::new(0),
            max_read_len: Cell::new(0),
            max_write_len: Cell::new(0),
            pending_read_ibi_len_bytes: 0,
            tx_buffer: TakeCell::empty(),
        }
    }

    /// Sets how many bytes of the response length (big-endian) follow the MDB
    /// in the pending-read IBI.
    ///
    /// 0 (default) sends the MDB only, as DSP0233 defines and Linux
    /// `mctp-i3c` expects: the controller reads up to MRL and the target ends
    /// the transfer on the T-bit. A non-zero value is for controllers that
    /// must know the private-read length in advance. 1 lowers the MTU to 254,
    /// because one byte cannot hold a longer read length.
    pub fn with_pending_read_ibi_len_bytes(mut self, len_bytes: usize) -> Self {
        assert!(len_bytes <= MAX_IBI_PAYLOAD_LEN.min(core::mem::size_of::<u32>()));
        self.pending_read_ibi_len_bytes = len_bytes;
        self
    }

    pub fn setup_mctp_i3c(&self) {
        let device_info = self.i3c_target.get_device_info();
        assert!((MCTP_I3C_MIN_PACKET_SIZE..=MCTP_I3C_MAXBUF).contains(&device_info.max_read_len));
        assert!((MCTP_I3C_MIN_PACKET_SIZE..=MCTP_I3C_MAXBUF).contains(&device_info.max_write_len));
        self.max_read_len.set(device_info.max_read_len);
        self.max_write_len.set(device_info.max_write_len);
        self.device_address.set(
            device_info
                .dynamic_addr
                .unwrap_or(device_info.static_addr.unwrap_or(0)),
        );
    }

    /// Largest private-read length whose value fits in the pending-read IBI's
    /// length bytes.
    fn effective_max_read_len(&self) -> usize {
        let max_read_len = self.max_read_len.get();
        match self.pending_read_ibi_len_bytes {
            0 => max_read_len,
            n if n >= core::mem::size_of::<u32>() => max_read_len,
            n => max_read_len.min((1usize << (8 * n)) - 1),
        }
    }

    /// SMBus CRC8 calculation.
    fn compute_pec(addr: u8, buf: &[u8], len: usize) -> u8 {
        let mut crc = 0u8;

        crc = caliptra_mcu_romtime::crc8(crc, addr);

        for byte in buf.iter().take(len) {
            crc = caliptra_mcu_romtime::crc8(crc, *byte);
        }
        crc
    }
}

impl<'a> MCTPTransportBinding<'a> for MCTPI3CBinding<'a> {
    fn set_tx_client(&self, tx_client: &'a dyn TransportTxClient) {
        self.tx_client.set(tx_client);
    }

    fn set_rx_client(&self, rx_client: &'a dyn TransportRxClient) {
        self.rx_client.set(rx_client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]) {
        self.i3c_target.set_rx_buffer(rx_buf);
    }

    fn transmit(
        &self,
        tx_buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        self.tx_buffer.replace(tx_buffer);

        // TX is a controller read. Reserve one byte of its limit for PEC.
        let max_payload_len = self.effective_max_read_len().saturating_sub(1);
        if len == 0 || len > max_payload_len {
            capsule_debug!("MCTP", "Invalid length. Expected: {}", max_payload_len);
            Err((ErrorCode::SIZE, self.tx_buffer.take().unwrap()))?;
        }

        // The controller reads the packet plus the PEC byte.
        let read_len = len + 1;
        let read_len_be = (read_len as u32).to_be_bytes();
        let len_bytes = self.pending_read_ibi_len_bytes;

        // Tx is a read operation from the I3C controller. Set the R/W bit at LSB to 1.
        let addr = (self.device_address.get() << 1) | 0x01;
        match self.tx_buffer.take() {
            Some(tx_buffer) => {
                if tx_buffer.len() > len {
                    let pec = MCTPI3CBinding::compute_pec(addr, tx_buffer, len);
                    tx_buffer[len] = pec;

                    match self.i3c_target.transmit_read(tx_buffer, read_len) {
                        Ok(_) => {
                            let payload = &read_len_be[read_len_be.len() - len_bytes..];
                            if let Err(e) = self.i3c_target.send_ibi(MCTP_PENDING_READ_MDB, payload)
                            {
                                capsule_error!("MCTP-I3C", "Pending-read IBI failed: {:?}", e);
                            }
                        }
                        Err((e, tx_buffer)) => {
                            Err((e, tx_buffer))?;
                        }
                    }
                } else {
                    capsule_debug!("MCTP-I3C", "Invalid length. Expected: {}", len + 1);
                    Err((ErrorCode::SIZE, tx_buffer))?;
                }
            }
            None => {
                Err((ErrorCode::FAIL, self.tx_buffer.take().unwrap()))?;
            }
        }
        Ok(())
    }

    fn enable(&self) {
        self.i3c_target.enable();
    }

    fn disable(&self) {
        self.i3c_target.disable();
    }

    fn get_mtu_size(&self) -> usize {
        self.effective_max_read_len() - 1
    }

    fn get_hdr_size(&self) -> usize {
        0
    }
}

impl TxClient for MCTPI3CBinding<'_> {
    fn send_done(&self, tx_buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.tx_client.map(|client| {
            client.send_done(tx_buffer, result);
        });
    }
}

impl RxClient for MCTPI3CBinding<'_> {
    fn receive_write(&self, rx_buffer: &'static mut [u8], len: usize) {
        // check if len is > 0 and <= max_write_len
        // if yes, compute PEC and check if it matches with the last byte of the buffer
        // if yes, call the client's receive_write function
        // if no, drop the packet and set_rx_buffer on i3c_target to receive the next packet
        if len == 0 || len > self.max_write_len.get() || len > rx_buffer.len() {
            self.i3c_target.set_rx_buffer(rx_buffer);
            return;
        }
        // Rx is a write operation from the I3C controller. Set the R/W bit at LSB to 0.
        let addr = self.device_address.get() << 1;
        let pec = MCTPI3CBinding::compute_pec(addr, rx_buffer, len - 1);
        if pec == rx_buffer[len - 1] {
            self.rx_client.map(|client| {
                client.receive(rx_buffer, len - 1);
            });
        } else {
            capsule_debug!(
                "MCTP",
                "Invalid PEC {:02x} (expected {:02x}) for address {:02x}. Dropping packet. len={}",
                rx_buffer[len - 1],
                pec,
                addr >> 1,
                len,
            );
            self.i3c_target.set_rx_buffer(rx_buffer);
        }
    }

    fn write_expected(&self) {
        self.rx_client.map(|client| {
            client.write_expected();
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Records what the binding hands to the I3C target.
    struct TestTarget {
        max_read_len: usize,
        wire_len: Cell<usize>,
        rx_buffer: TakeCell<'static, [u8]>,
        ibi: Cell<Option<(u8, [u8; 4], usize)>>,
    }

    impl TestTarget {
        fn new(max_read_len: usize) -> Self {
            Self {
                max_read_len,
                wire_len: Cell::new(0),
                rx_buffer: TakeCell::empty(),
                ibi: Cell::new(None),
            }
        }

        fn ibi_payload(&self) -> (u8, Vec<u8>) {
            let (mdb, payload, len) = self.ibi.get().expect("no IBI sent");
            (mdb, payload[..len].to_vec())
        }
    }

    impl<'a> I3CTarget<'a> for TestTarget {
        fn set_tx_client(&self, _client: &'a dyn TxClient) {}
        fn set_rx_client(&self, _client: &'a dyn RxClient) {}
        fn set_rx_buffer(&self, buffer: &'static mut [u8]) {
            self.rx_buffer.replace(buffer);
        }
        fn transmit_read(
            &self,
            _buffer: &'static mut [u8],
            len: usize,
        ) -> Result<(), (ErrorCode, &'static mut [u8])> {
            self.wire_len.set(len);
            Ok(())
        }
        fn send_ibi(&self, mdb: u8, payload: &[u8]) -> Result<(), ErrorCode> {
            let mut saved = [0u8; 4];
            saved[..payload.len()].copy_from_slice(payload);
            self.ibi.set(Some((mdb, saved, payload.len())));
            Ok(())
        }
        fn enable(&self) {}
        fn disable(&self) {}
        fn get_device_info(&self) -> caliptra_mcu_i3c_driver::hil::I3CTargetInfo {
            caliptra_mcu_i3c_driver::hil::I3CTargetInfo {
                static_addr: Some(0x10),
                dynamic_addr: None,
                max_read_len: self.max_read_len,
                max_write_len: MCTP_I3C_MAXBUF,
            }
        }
    }

    #[test]
    fn transmit_uses_read_limit_including_pec() {
        let target = TestTarget::new(MCTP_I3C_MIN_PACKET_SIZE);
        let binding = MCTPI3CBinding::new(&target);
        binding.setup_mctp_i3c();
        let buffer = Box::leak(Box::new([0; MCTP_I3C_MIN_PACKET_SIZE + 1]));
        let ptr = buffer.as_ptr();
        let (error, buffer) = binding
            .transmit(buffer, MCTP_I3C_MIN_PACKET_SIZE)
            .unwrap_err();
        assert_eq!(error, ErrorCode::SIZE);
        assert_eq!(buffer.as_ptr(), ptr);
        assert_eq!(target.wire_len.get(), 0);
        binding
            .transmit(buffer, MCTP_I3C_MIN_PACKET_SIZE - 1)
            .unwrap();
        assert_eq!(target.wire_len.get(), MCTP_I3C_MIN_PACKET_SIZE);
    }

    #[test]
    fn receive_returns_buffer_for_invalid_lengths() {
        for len in [0, 3, MCTP_I3C_MAXBUF + 1] {
            let target = TestTarget::new(MCTP_I3C_MIN_PACKET_SIZE);
            let binding = MCTPI3CBinding::new(&target);
            binding.setup_mctp_i3c();
            let buffer = Box::leak(Box::new([0xA5; 2]));
            let ptr = buffer.as_ptr();

            binding.receive_write(buffer, len);

            let buffer = target.rx_buffer.take().unwrap();
            assert_eq!(buffer.as_ptr(), ptr);
            assert_eq!(buffer, &[0xA5; 2]);
        }
    }

    fn calculate_crc8(data: &[u8]) -> u8 {
        let polynomial = 0x07;
        let mut crc = 0u8;

        for &byte in data {
            crc ^= byte;
            for _ in 0..8 {
                if crc & 0x80 != 0 {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }

    #[test]
    fn test_crc8() {
        assert_eq!(0xf4, calculate_crc8(b"123456789"));
    }

    #[test]
    fn test_mctp_i3c_packet_size_limits() {
        assert_eq!(MCTP_I3C_MIN_PACKET_SIZE, 69);
        assert_eq!(MCTP_I3C_MAXBUF, 256);
        assert_eq!(MCTP_I3C_MAXMTU, 255);
    }

    #[test]
    fn test_pec_for_req() {
        // Write to device address 0x10
        let dev_addr = 0x10 << 1;
        // header version 0x01, src EID 0x00, dest EID 0x08, som = 1, eom = 1, pkt_seq = 0, tag_owner = 1, msg_tag = 1
        let mctp_hdr = [0x01, 0x00, 0x08, 0xC9];
        // (IC, control message type) = 0x00, Request packet (0x80), set EID command = 0x01
        let msg_hdr = [0x00, 0x80, 0x1];
        // msg payload: op = 0x00, EID = 0x0A
        let msg = [0x00, 0x0A];

        let pkt_buf_len = 1 + mctp_hdr.len() + msg_hdr.len() + msg.len();

        let pkt: &mut [u8] = &mut [0; MCTP_I3C_MAXBUF];
        pkt[0] = dev_addr;
        pkt[1..1 + mctp_hdr.len()].copy_from_slice(&mctp_hdr);
        pkt[1 + mctp_hdr.len()..1 + mctp_hdr.len() + msg_hdr.len()].copy_from_slice(&msg_hdr);
        pkt[1 + mctp_hdr.len() + msg_hdr.len()..pkt_buf_len].copy_from_slice(&msg);

        let computed_pec =
            MCTPI3CBinding::compute_pec(dev_addr, &pkt[1..pkt_buf_len], pkt_buf_len - 1);
        let exp_pec = calculate_crc8(&pkt[..pkt_buf_len]);
        assert_eq!(exp_pec, computed_pec);
    }

    #[test]
    fn test_pec_for_resp() {
        let dev_addr = (0x10 << 1) | 0x01;
        // header version 0x01, src EID 0x00, dest EID 0x08, som = 1, eom = 1, pkt_seq = 0, tag_owner = 0, msg_tag = 1
        let mctp_hdr = [0x01, 0x00, 0x08, 0xC1];
        // (IC, control message type) = 0x00, Response packet (0x00), set EID command = 0x01
        let msg_hdr = [0x00, 0x00, 0x01];
        // msg payload: completion code = 0x00, byte 2 : (0x00), EID = 0x0A, byte 4: (0x00)
        let msg = [0x00, 0x00, 0x0A, 0x00];

        let pkt_buf_len = 1 + mctp_hdr.len() + msg_hdr.len() + msg.len();
        let pkt: &mut [u8] = &mut [0; MCTP_I3C_MAXBUF];
        pkt[0] = dev_addr;
        pkt[1..1 + mctp_hdr.len()].copy_from_slice(&mctp_hdr);
        pkt[1 + mctp_hdr.len()..1 + mctp_hdr.len() + msg_hdr.len()].copy_from_slice(&msg_hdr);
        pkt[1 + mctp_hdr.len() + msg_hdr.len()..pkt_buf_len].copy_from_slice(&msg);

        let computed_pec =
            MCTPI3CBinding::compute_pec(dev_addr, &pkt[1..pkt_buf_len], pkt_buf_len - 1);
        let exp_pec = calculate_crc8(&pkt[..pkt_buf_len]);
        assert_eq!(exp_pec, computed_pec);
    }

    fn packet(len: usize) -> &'static mut [u8] {
        let buf = Box::leak(Box::new([0u8; MCTP_I3C_MAXBUF]));
        for (i, b) in buf[..len].iter_mut().enumerate() {
            *b = i as u8;
        }
        buf
    }

    #[test]
    fn pending_read_ibi_is_mdb_only_by_default() {
        let target = TestTarget::new(MCTP_I3C_MAXBUF);
        let binding = MCTPI3CBinding::new(&target);
        binding.setup_mctp_i3c();

        binding.transmit(packet(10), 10).unwrap();

        assert_eq!(target.wire_len.get(), 11);
        assert_eq!(target.ibi_payload(), (MCTP_PENDING_READ_MDB, vec![]));
    }

    #[test]
    fn pending_read_ibi_appends_big_endian_read_length() {
        let target = TestTarget::new(MCTP_I3C_MAXBUF);
        let binding = MCTPI3CBinding::new(&target).with_pending_read_ibi_len_bytes(2);
        binding.setup_mctp_i3c();

        binding.transmit(packet(255), 255).unwrap();

        // read length includes the PEC byte: 256 = 0x0100, MSB first
        assert_eq!(
            target.ibi_payload(),
            (MCTP_PENDING_READ_MDB, vec![0x01, 0x00])
        );
    }

    #[test]
    fn one_length_byte_rejects_packet_above_mtu() {
        let target = TestTarget::new(MCTP_I3C_MAXBUF);
        let binding = MCTPI3CBinding::new(&target).with_pending_read_ibi_len_bytes(1);
        binding.setup_mctp_i3c();

        // one length byte limits the MTU to 254
        let (err, _) = binding.transmit(packet(255), 255).unwrap_err();

        assert_eq!(err, ErrorCode::SIZE);
        assert_eq!(target.wire_len.get(), 0);
        assert!(target.ibi.get().is_none());
    }

    #[test]
    fn mtu_follows_pending_read_ibi_len_bytes() {
        let target = TestTarget::new(MCTP_I3C_MAXBUF);
        for (len_bytes, mtu) in [(0, 255), (1, 254), (2, 255), (4, 255)] {
            let binding = MCTPI3CBinding::new(&target).with_pending_read_ibi_len_bytes(len_bytes);
            binding.setup_mctp_i3c();
            assert_eq!(binding.get_mtu_size(), mtu, "len_bytes = {len_bytes}");
        }
    }

    #[test]
    fn one_length_byte_sends_full_mtu_packet() {
        let target = TestTarget::new(MCTP_I3C_MAXBUF);
        let binding = MCTPI3CBinding::new(&target).with_pending_read_ibi_len_bytes(1);
        binding.setup_mctp_i3c();

        binding.transmit(packet(254), 254).unwrap();

        assert_eq!(target.wire_len.get(), 255);
        assert_eq!(target.ibi_payload(), (MCTP_PENDING_READ_MDB, vec![0xFF]));
    }
}
