// Licensed under the Apache-2.0 license

use crate::{sleep_emulator_ticks, tests::doe_util::protocol::*};
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use zerocopy::IntoBytes;

pub struct DoeUtil;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoeUtilError {
    InvalidDataLength,
    SendError(SendError<Vec<u8>>),
    ReceiveError(RecvError),
}

impl DoeUtil {
    pub fn send_data_object(
        data: &[u8],
        object_type: DataObjectType,
        tx: &mut Sender<Vec<u8>>,
    ) -> Result<(), DoeUtilError> {
        if data.is_empty() || data.len() % 4 != 0 {
            println!("DOE_UTIL: Data length must be non-zero and a multiple of 4 bytes.");
            return Err(DoeUtilError::InvalidDataLength);
        }

        let len = data.len() as u32 + DOE_DATA_OBJECT_HEADER_LEN as u32;

        println!("DOE_UTIL: Sending DOE data object");
        let header = DoeHeader::new(object_type, len);

        let header_bytes = header.as_bytes();
        let mut data_vec = Vec::new();

        // add doe header and send
        data_vec.extend(header_bytes);
        data_vec.extend_from_slice(data);
        if let Err(e) = tx.send(data_vec) {
            println!("DOE_UTIL: Failed to send DOE data object: {:?}", e);
            Err(DoeUtilError::SendError(e))
        } else {
            println!("DOE_UTIL: DOE data object sent successfully.");
            Ok(())
        }
    }

    pub fn send_raw_data_object(data: &[u8], tx: &mut Sender<Vec<u8>>) -> Result<(), DoeUtilError> {
        if data.is_empty() || data.len() % 4 != 0 {
            println!("DOE_UTIL: Data length must be non-zero and a multiple of 4 bytes.");
            return Err(DoeUtilError::InvalidDataLength);
        }

        if let Err(e) = tx.send(data.to_vec()) {
            println!("DOE_UTIL: Failed to send raw data: {:?}", e);
            Err(DoeUtilError::SendError(e))
        } else {
            println!("DOE_UTIL: Raw data sent successfully.");
            Ok(())
        }
    }

    pub fn receive_data_object(rx: &Receiver<Vec<u8>>) -> Result<Vec<u8>, DoeUtilError> {
        match rx.try_recv() {
            Ok(message) => {
                println!("DOE_UTIL: Received DOE data object");

                if message.len() < DOE_DATA_OBJECT_HEADER_LEN {
                    println!("DOE_UTIL: Received data object is too short.");
                    return Err(DoeUtilError::InvalidDataLength);
                }
                let output = message[DOE_DATA_OBJECT_HEADER_LEN..].to_vec();
                Ok(output)
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(vec![]),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                println!("DOE_UTIL: Receiver has disconnected.");
                Err(DoeUtilError::ReceiveError(RecvError))
            }
        }
    }

    pub fn receive_raw_data_object(rx: &Receiver<Vec<u8>>) -> Result<Vec<u8>, DoeUtilError> {
        // TODO: this should not need to be so high.
        // Nothing should take >3,500,000 ticks to respond,
        // but setting it to 35 will fail tests.
        for _ in 0..60 {
            match rx.try_recv() {
                Ok(message) => {
                    println!(
                        "DOE_UTIL: Received raw data object with length: {}",
                        message.len()
                    );
                    return Ok(message);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    sleep_emulator_ticks(100_000);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    println!("DOE_UTIL: Receiver has disconnected.");
                    return Err(DoeUtilError::ReceiveError(RecvError));
                }
            }
        }
        Ok(Vec::new())
    }
}
