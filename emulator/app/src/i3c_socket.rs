/*++

Licensed under the Apache-2.0 license.

File Name:

    i3c_socket.rs

Abstract:

    I3C over TCP socket implementation.

    The protocol is byte-based and is relatively simple.

    The server is running and will forward all responses from targets in the emulator to the client.
    Data written to the server is interpreted as a command.

     and sends commands, and the client is one (or more)
    more targets who can only respond or send IBIs.

    The server will read (and the client will write) packets of the form:
    to_addr: u8
    command_descriptor: [u8; 8]
    data: [u8; N] // length is in the descriptor

    The server will write (and the client will read) packets of the form:
    ibi: u8,
    from_addr: u8
    response_descriptor: [u8; 4]
    data: [u8; N] // length is in the descriptor

    If the ibi field is non-zero, then it should be interpreted as the MDB for the IBI.

--*/

use emulator_periph::{
    I3cBusCommand, I3cBusResponse, I3cTcriCommand, I3cTcriCommandXfer, ResponseDescriptor,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc};
use zerocopy::{transmute, FromBytes, IntoBytes};

pub(crate) fn start_i3c_socket(
    running: Arc<AtomicBool>,
    port: u16,
) -> (Receiver<I3cBusCommand>, Sender<I3cBusResponse>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .expect("Failed to bind TCP socket for port");

    let (bus_command_tx, bus_command_rx) = mpsc::channel::<I3cBusCommand>();
    let (bus_response_tx, bus_response_rx) = mpsc::channel::<I3cBusResponse>();
    let running_clone = running.clone();
    std::thread::spawn(move || {
        handle_i3c_socket_loop(running_clone, listener, bus_response_rx, bus_command_tx)
    });

    (bus_command_rx, bus_response_tx)
}

fn handle_i3c_socket_loop(
    running: Arc<AtomicBool>,
    listener: TcpListener,
    mut bus_response_rx: Receiver<I3cBusResponse>,
    mut bus_command_tx: Sender<I3cBusCommand>,
) {
    listener
        .set_nonblocking(true)
        .expect("Could not set non-blocking");
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, addr)) => {
                handle_i3c_socket_connection(
                    running.clone(),
                    stream,
                    addr,
                    &mut bus_response_rx,
                    &mut bus_command_tx,
                );
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("Error accepting connection: {}", e),
        }
    }
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
struct IncomingHeader {
    to_addr: u8,
    command: [u32; 2],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
struct OutgoingHeader {
    ibi: u8,
    from_addr: u8,
    response_descriptor: ResponseDescriptor,
}

fn handle_i3c_socket_connection(
    running: Arc<AtomicBool>,
    mut stream: TcpStream,
    _addr: SocketAddr,
    bus_response_rx: &mut Receiver<I3cBusResponse>,
    bus_command_tx: &mut Sender<I3cBusCommand>,
) {
    let stream = &mut stream;
    stream.set_nonblocking(true).unwrap();

    while running.load(Ordering::Relaxed) {
        // try reading
        let mut incoming_header_bytes = [0u8; 9];
        match stream.read_exact(&mut incoming_header_bytes) {
            Ok(()) => {
                let incoming_header: IncomingHeader = transmute!(incoming_header_bytes);
                let cmd: I3cTcriCommand = incoming_header.command.try_into().unwrap();
                let mut data = vec![0u8; cmd.data_len()];
                stream.set_nonblocking(false).unwrap();
                stream
                    .read_exact(&mut data)
                    .expect("Failed to read message from socket");
                stream.set_nonblocking(true).unwrap();
                let bus_command = I3cBusCommand {
                    addr: incoming_header.to_addr.into(),
                    cmd: I3cTcriCommandXfer { cmd, data },
                };
                bus_command_tx.send(bus_command).unwrap();
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
        match bus_response_rx.try_recv() {
            Ok(response) => {
                let data_len = response.resp.data.len();
                if data_len > 255 {
                    panic!("Cannot write more than 255 bytes to socket");
                }
                let outgoing_header = OutgoingHeader {
                    ibi: response.ibi.unwrap_or_default(),
                    from_addr: response.addr.into(),
                    response_descriptor: response.resp.resp,
                };
                let header_bytes: [u8; 6] = transmute!(outgoing_header);
                stream.write_all(&header_bytes).unwrap();
                stream.write_all(&response.resp.data).unwrap();
            }
            Err(e) => panic!("Error writing to socket: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::i3c_socket::*;
    use zerocopy::transmute;

    #[test]
    fn test_into_bytes() {
        let idata = IncomingHeader {
            to_addr: 10,
            command: [0x01020304, 0x05060708],
        };
        let serialized: [u8; 9] = transmute!(idata);
        assert_eq!("0a0403020108070605", hex::encode(serialized));
        let odata = OutgoingHeader {
            ibi: 0,
            from_addr: 10,
            response_descriptor: ResponseDescriptor(0x01020304),
        };
        let serialized: [u8; 6] = transmute!(odata);
        assert_eq!("000a04030201", hex::encode(serialized));
    }
}
