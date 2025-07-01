// Licensed under the Apache-2.0 license
use crate::doe::protocol::*;
use core::cell::Cell;
use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient};
use kernel::debug;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::{ErrorCode, ProcessId};
use romtime::println;

pub const DOE_SPDM_DRIVER_NUM: usize = 0xA000_0010;

/// IDs for subscribe calls
mod upcall {
    /// Callback for when the message is received
    pub const MESSAGE_RECEIVED: usize = 0;

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
    pub const MESSAGE_READ: usize = 0;

    /// Number of read-write allow buffers
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a message is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a message is in progress
}

pub struct DoeDriver<'a, T: DoeTransport<'a>> {
    doe_transport: &'a T,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: OptionalCell<ProcessId>,
}

impl<'a, T: DoeTransport<'a>> DoeDriver<'a, T> {
    pub fn new(
        doe_transport: &'a T,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        DoeDriver {
            doe_transport,
            apps: grant,
            current_app: OptionalCell::empty(),
        }
    }

    fn start_transmit(&self, app_buf: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        // Ensure the buffer is large enough
        let data_len_bytes = app_buf.len();
        if data_len_bytes % 4 != 0 {
            return Err(ErrorCode::INVAL);
        }

        // Transmit the message
        self.doe_transport.transmit(
            app_buf.chunks(4).map(|chunk| {
                let mut dword = [0u8; 4];
                chunk.copy_to_slice(&mut dword);
                u32::from_le_bytes(dword)
            }),
            data_len_bytes / 4,
        )
    }

    fn send_app_data(
        &self,
        process_id: ProcessId,
        app: &mut App,
        kernel_data: &GrantKernelData,
    ) -> Result<(), ErrorCode> {
        self.current_app.set(process_id);

        let _result = kernel_data
            .get_readonly_processbuffer(ro_allow::MESSAGE_WRITE)
            .map_err(|e| {
                debug!("Error getting ReadOnlyProcessBuffer buffer: {:?}", e);
                ErrorCode::INVAL
            })
            .and_then(|tx_buf| {
                tx_buf
                    .enter(|app_buf| self.start_transmit(app_buf))
                    .map_err(|e| {
                        debug!("Error getting application tx buffer: {:?}", e);
                        ErrorCode::FAIL
                    })
            })?;

        app.pending_tx.set(true);
        Ok(())
    }

    fn handle_doe_discovery(&self, doe_req: DoeDiscoveryRequest) {
        let data_object_protocol = DataObjectType::from(doe_req.index());
        if data_object_protocol == DataObjectType::Unsupported {
            debug!("Unsupported DOE Discovery Request");
            return;
        }

        let next_index = (data_object_protocol as u8 + 1) % NUM_DATA_OBJECT_PROTOCOL_TYPES as u8;

        let mut doe_resp = [0u32; DOE_DISCOVERY_DATA_OBJECT_LEN_DW];

        // Prepare the DOE Discovery Response
        let discovery_response = DoeDiscoveryResponse::new(data_object_protocol as u8, next_index);

        // Prepare the response buffer
        let doe_header = DoeDataObjectHeader::new(
            data_object_protocol,
            DOE_DISCOVERY_DATA_OBJECT_LEN_DW as u32,
        );
        if doe_header
            .encode(&mut doe_resp[..DOE_DATA_OBJECT_HEADER_LEN_DW])
            .is_err()
        {
            debug!("Error encoding DOE header");
            return;
        }
        if discovery_response
            .encode(&mut doe_resp[DOE_DATA_OBJECT_HEADER_LEN_DW..])
            .is_err()
        {
            debug!("Error encoding DOE discovery response");
            return;
        }

        // Transmit the DOE Discovery Response

        match self
            .doe_transport
            .transmit(doe_resp.iter().copied(), doe_resp.len())
        {
            Ok(_) => debug!("DOE Discovery Response transmitted successfully"),
            Err(err) => debug!("Error transmitting DOE Discovery Response: {:?}", err),
        };
    }

    fn handle_spdm_upcall(&self, rx_buf: &'static mut [u32], len_dw: usize) {
        // Handle SPDM Data Object
        debug!("Handling SPDM Data Object with length: {} dwords", len_dw);

        self.apps.each(|_, app, kernel_data| {
            if app.waiting_rx.get() {
                app.waiting_rx.set(false);
            } else {
                debug!("Application not waiting for Data Object");
                return;
            }

            let read_len: Result<Result<usize, ErrorCode>, ErrorCode> =
                match kernel_data.get_readwrite_processbuffer(rw_allow::MESSAGE_READ) {
                    Ok(read_buf) => {
                        let copy_len_dw = core::cmp::min(read_buf.len() / 4, len_dw);
                        read_buf
                            .mut_enter(|app_buf| {
                                for (i, &data) in rx_buf.iter().enumerate().take(copy_len_dw) {
                                    let start = i * 4;
                                    let end = start + 4;
                                    let bytes = data.to_le_bytes();
                                    app_buf[start..end].copy_from_slice(&bytes);
                                }
                                Ok(copy_len_dw * 4)
                            })
                            .map_err(|e| {
                                debug!("Error entering ReadWriteProcessBuffer buffer");
                                e.into()
                            })
                    }
                    Err(err) => {
                        debug!("Error getting ReadWriteProcessBuffer buffer: {:?}", err);
                        Err(ErrorCode::INVAL)
                    }
                };

            match read_len {
                Ok(Ok(len)) => {
                    debug!("SPDM Data Object received successfully, length: {}", len);
                    kernel_data
                        .schedule_upcall(upcall::MESSAGE_RECEIVED, (len, 0, 0))
                        .ok();
                }
                Ok(Err(err)) => {
                    debug!("Error copying data to app buffer: {:?}", err);
                }
                Err(err) => {
                    debug!("Error copying data to app buffer: {:?}", err);
                }
            }
        });

        self.doe_transport.set_rx_buffer(rx_buf);
    }
}

impl<'a, T: DoeTransport<'a>> SyscallDriver for DoeDriver<'a, T> {
    /// MCTP Capsule command
    ///
    /// ### `command_num`
    ///
    /// - `0`: Driver check.
    ///
    /// - `1`: Receive message. Issues upcall when driver receives a SPDM/Secure SPDM Data object type
    /// - `2`: Send message. Sends the received message to the DOE transport layer. Schedules an upcall
    ///   when the message is sent.
    /// - `3`: Max message size. Returns the maximum message size supported by the DOE transport layer.
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
                    app.waiting_rx.set(true);
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
                        if app.pending_tx.get() {
                            return Err(ErrorCode::BUSY);
                        }

                        self.send_app_data(process_id, app, kernel_data)
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
            3 => {
                // Get Max Data Object Size
                let max_size_dw = self.doe_transport.max_data_object_size_dw();
                CommandReturn::success_u32((max_size_dw * 4) as u32)
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

impl<'a, T: DoeTransport<'a>> DoeTransportRxClient for DoeDriver<'a, T> {
    fn receive(&self, rx_buf: &'static mut [u32], len: usize) {
        if len < 3 || len > rx_buf.len() {
            println!("DOE_CAPSULE: Invalid length received: {}", len);
            self.doe_transport.set_rx_buffer(rx_buf);
            return;
        }
        // Decode the DOE header
        println!("DOE_CAPSULE: Received DOE Data Object with length: {}", len);

        let doe_hdr = match DoeDataObjectHeader::decode(rx_buf) {
            Ok(header) => header,
            Err(_) => {
                println!("DOE_CAPSULE: Failed to decode DOE header");
                self.doe_transport.set_rx_buffer(rx_buf);
                return;
            }
        };

        if !doe_hdr.validate(len as u32) {
            println!("DOE_CAPSULE: Invalid DOE Data Object");
            self.doe_transport.set_rx_buffer(rx_buf);
            return;
        }

        println!(
            "DOE_CAPSULE: Received DOE Data Object: vendor_id: {}, type: {:?}, length: {}",
            doe_hdr.vendor_id,
            doe_hdr.data_object_type(),
            doe_hdr.length
        );

        match doe_hdr.data_object_type() {
            DataObjectType::DoeDiscovery => {
                let doe_req_dw = rx_buf[DOE_DATA_OBJECT_HEADER_LEN_DW];
                self.doe_transport.set_rx_buffer(rx_buf);
                let doe_req = DoeDiscoveryRequest::decode(doe_req_dw);
                self.handle_doe_discovery(doe_req);
            }
            DataObjectType::Spdm | DataObjectType::SecureSpdm => {
                self.handle_spdm_upcall(rx_buf, len);
                // Note: rx_buf is consumed by handle_spdm_upcall, so we don't call set_rx_buffer here
            }
            DataObjectType::Unsupported => {
                debug!("Unsupported DOE Data Object");
                self.doe_transport.set_rx_buffer(rx_buf);
            }
        }
    }
}

impl<'a, T: DoeTransport<'a>> DoeTransportTxClient<'a> for DoeDriver<'a, T> {
    fn send_done(&self, result: Result<(), ErrorCode>) {
        // Handle transmission completion
        if let Some(process_id) = self.current_app.get() {
            let _ = self.apps.enter(process_id, |app, kernel_data| {
                app.pending_tx.set(false);
                kernel_data
                    .schedule_upcall(upcall::MESSAGE_TRANSMITTED, (result.is_ok() as usize, 0, 0))
                    .ok();
            });
        }
    }
}
