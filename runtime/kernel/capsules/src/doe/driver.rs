use core::u32::MIN;

// Licensed under the Apache-2.0 license
use crate::doe::{self, protocol::*};
use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient};
use kernel::debug;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};
use registers_generated::i3c::bits::DeviceId0::Data;

/// IDs for subscribe calls
mod upcall {
    /// Callback for when the message is received
    pub const RECEIVED_MESSAGE: usize = 0;

    /// Callback for when the message is transmitted.
    pub const MESSAGE_TRANSMITTED: usize = 1;

    /// Number of upcalls
    pub const COUNT: u8 = 2;
}

/// IDs for read-only allow buffers
mod ro_allow {
    /// Buffer for the message to be transmitted
    pub const MESSAGE_WRITE: usize = 0;

    /// Number of read-only allow buffers
    pub const COUNT: u8 = 1;
}

/// IDs for read-write allow buffers
mod rw_allow {
    /// Buffer for the message to be received
    pub const MESSAGE_READ: u32 = 0;

    /// Number of read-write allow buffers
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App {
    waiting_rx: Option<bool>, // Indicates if a message is waiting to be received
    pending_tx: Option<bool>, // Indicates if a message is in progress
}

pub struct DoeDriver<'a> {
    doe_transport: &'a dyn DoeTransport,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    kernel_rx_buf: TakeCell<'static, [u32]>,
    kernel_tx_buf: TakeCell<'static, [u32]>,
    current_app: OptionalCell<ProcessId>,
}

impl<'a> DoeDriver<'a> {
    pub fn new(
        doe_transport: &'a dyn DoeTransport,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        tx_buf: &'static mut [u32],
        rx_buf: &'static mut [u32],
    ) -> Self {
        DoeDriver {
            doe_transport,
            apps: grant,
            kernel_tx_buf: TakeCell::new(tx_buf),
            kernel_rx_buf: TakeCell::new(rx_buf),
            current_app: OptionalCell::empty(),
        }
    }

    fn transmit_message(
        &self,
        app_buf: &ReadableProcessSlice,
        tx_buf: &'static mut [u32],
    ) -> Result<(), ErrorCode> {
        // Ensure the buffer is large enough
        let data_len_bytes = app_buf.len();
        let data_len_dwords = data_len_bytes / 4;
        if data_len_bytes > tx_buf.len() * 4 {
            return Err(ErrorCode::SIZE);
        }
        if data_len_bytes % 4 != 0 {
            return Err(ErrorCode::INVAL);
        }

        // Copy the data from the application buffer to the kernel buffer
        app_buf.chunks(4).enumerate().for_each(|(i, chunk)| {
            let mut dest = [0u8; 4];
            chunk.copy_to_slice(&mut dest);
            tx_buf[i] = u32::from_le_bytes(dest);
        });

        // Transmit the message
        self.doe_transport
            .transmit(tx_buf, data_len_dwords)
            .map_err(|(err, buf)| {
                debug!("Error transmitting message: {:?}", err);
                self.kernel_tx_buf.replace(buf);
                ErrorCode::FAIL
            })
    }

    fn send(
        &self,
        process_id: ProcessId,
        app: &mut App,
        kernel_data: &GrantKernelData,
    ) -> Result<(), ErrorCode> {
        self.current_app.set(process_id);

        kernel_data
            .get_readonly_processbuffer(ro_allow::MESSAGE_WRITE)
            .map_err(|e| {
                debug!("Error getting ReadOnlyProcessBuffer buffer: {:?}", e);
                ErrorCode::INVAL
            })
            .and_then(|tx_buf| {
                tx_buf
                    .enter(|app_buf| match self.kernel_tx_buf.take() {
                        Some(tx_buf) => self.transmit_message(app_buf, tx_buf),
                        None => {
                            debug!("Kernel transmit buffer not available");
                            Err(ErrorCode::NOMEM)
                        }
                    })
                    .map_err(|e| {
                        debug!("Error getting application tx buffer: {:?}", e);
                        ErrorCode::FAIL
                    })
            })?;

        app.pending_tx = Some(true);
        Ok(())
    }

    fn handle_doe_discovery(&self, rx_buf: &'static mut [u32], len: usize) {
        let doe_req_dw = rx_buf[DOE_DATA_OBJECT_HEADER_LEN_DW as usize];
        let doe_req = DoeDiscoveryRequest::decode(doe_req_dw);
        let data_object_protocol = DataObjectType::from(doe_req.index());
        if data_object_protocol == DataObjectType::Unsupported {
            debug!("Unsupported DOE Discovery Request");
            return;
        }

        let next_index = (data_object_protocol as u8 + 1) % DataObjectType::SecureSpdm as u8;

        // Prepare the DOE Discovery Response
        let discovery_response = DoeDiscoveryResponse::new(data_object_protocol as u8, next_index);

        // Prepare the response buffer
        let doe_header = DoeDataObjectHeader::new(
            data_object_protocol,
            DOE_DISCOVERY_DATA_OBJECT_LEN_DW as u32,
        );
        doe_header.encode(rx_buf);
        discovery_response.encode(&mut rx_buf[DOE_DATA_OBJECT_HEADER_LEN_DW as usize..]);

        self.doe_transport
            .transmit(rx_buf, DOE_DISCOVERY_DATA_OBJECT_LEN_DW as usize)
            .map_err(|(err, buf)| {
                debug!("Error transmitting DOE Discovery Response: {:?}", err);
            });
    }

    fn handle_spdm_upcall(&self, rx_buf: &'static mut [u32], len: usize) {
        // Handle SPDM Data Object
        debug!("Handling SPDM Data Object with length: {}", len);

        // Set the kernel receive buffer
        if let Some(rx_buf) = self.kernel_rx_buf.take() {
            rx_buf[..len].copy_from_slice(&rx_buf[..len]);
            self.doe_transport.set_rx_buffer(rx_buf);
        } else {
            debug!("Kernel receive buffer not available");
        }

        // Notify the application via upcall
        self.apps
            .enter(self.current_app.get().unwrap(), |app, kernel_data| {
                app.waiting_rx = Some(false);
                app.pending_tx = Some(false);
                kernel_data.upcall(upcall::RECEIVED_MESSAGE, 0, 0);
            })
            .ok();
    }
}

impl<'a> SyscallDriver for DoeDriver<'a> {
    /// MCTP Capsule command
    ///
    /// ### `command_num`
    ///
    /// - `0`: Driver check.
    ///
    /// - `1`: Receive message. Issues upcall when driver receives a SPDM/Secure SPDM Data object type
    /// - `2`: Send message. Sends the received message to the DOE transport layer. Shedules an upcall
    ///  when the message is sent.
    ///
    fn command(
        &self,
        command_num: usize,
        _arg1: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => {
                // Receive Request Message
                let res = self.apps.enter(process_id, |app, _| {
                    app.waiting_rx = Some(true);
                });

                match res {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            2 => {
                // Send DOE Data Object
                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        if app.pending_tx.is_some() {
                            return Err(ErrorCode::BUSY);
                        }

                        self.send(process_id, app, kernel_data)
                    })
                    .map_err(|err| {
                        debug!("Error sending DOE Data object: {:?}", err);
                        err.into()
                    });
                match result {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => {
                        debug!("ErrorCode sending DOE Data object: {:?}", err);
                        CommandReturn::failure(err)
                    }
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

impl DoeTransportRxClient for DoeDriver<'_> {
    fn receive(&self, rx_buf: &'static mut [u32], len: usize) {
        if len < 3 || len > rx_buf.len() {
            debug!("Invalid length received: {}", len);
            self.kernel_rx_buf.replace(rx_buf);
            return;
        }
        // Debode the DOE header
        debug!("Received DOE Data Object with length: {}", len);

        let doe_hdr = match DoeDataObjectHeader::decode(rx_buf) {
            Some(header) => header,
            None => {
                debug!("Failed to decode DOE header");
                self.kernel_rx_buf.replace(rx_buf);
                return;
            }
        };

        if !doe_hdr.validate(len as u32) {
            debug!("Invalid DOE Data Object");
            self.kernel_rx_buf.replace(rx_buf);
            return;
        }

        debug!(
            "Received DOE Data Object: vendor_id: {}, type: {:?}, length: {}",
            doe_hdr.vendor_id,
            doe_hdr.data_object_type(),
            doe_hdr.length
        );

        match doe_hdr.data_object_type() {
            DataObjectType::DoeDiscovery => {
                self.handle_doe_discovery(rx_buf, len);
            }
            DataObjectType::Spdm | DataObjectType::SecureSpdm => {
                self.handle_spdm_upcall(rx_buf, len);
            }
            DataObjectType::Unsupported => {
                debug!("Unsupported DOE Data Object");
            }
        }
        self.kernel_rx_buf.replace(rx_buf);
    }

    fn receive_expected(&self) {
        // This function can be used to handle expected data reception
        // For now, we just set the state to Received
        if let Some(rx_buf) = self.kernel_rx_buf.take() {
            self.doe_transport.set_rx_buffer(rx_buf);
        } else {
            debug!("Kernel receive buffer not available");
        }
    }
}
impl DoeTransportTxClient for DoeDriver<'_> {
    fn send_done(&self, tx_buf: &'static mut [u8], result: Result<(), ErrorCode>) {
        todo!("Implement send_done logic for DoeDriver");
    }
}
