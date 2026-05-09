/*++

Licensed under the Apache-2.0 license.

File Name:

    i3c_socket_server.rs

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

use crate::i3c::{
    I3cBusCommand, I3cBusResponse, I3cTcriCommand, I3cTcriCommandXfer, ResponseDescriptor,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use std::vec;
use zerocopy::{transmute, FromBytes, IntoBytes};

pub const CRC8_SMBUS: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);

pub fn start_i3c_socket(
    running: &'static AtomicBool,
    port: u16,
) -> (Receiver<I3cBusCommand>, Sender<I3cBusResponse>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .expect("Failed to bind TCP socket for port");

    let (bus_command_tx, bus_command_rx) = mpsc::channel::<I3cBusCommand>();
    let (bus_response_tx, bus_response_rx) = mpsc::channel::<I3cBusResponse>();
    std::thread::spawn(move || {
        handle_i3c_socket_loop(running, listener, bus_response_rx, bus_command_tx)
    });

    (bus_command_rx, bus_response_tx)
}

pub fn handle_i3c_socket_loop(
    running: &'static AtomicBool,
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
                println!("Accepting I3C socket connection from {:?}", addr);
                handle_i3c_socket_connection(
                    running,
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
pub struct IncomingHeader {
    pub to_addr: u8,
    pub command: [u32; 2],
}

#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct OutgoingHeader {
    pub ibi: u8,
    pub from_addr: u8,
    pub response_descriptor: ResponseDescriptor,
}

fn handle_i3c_socket_connection(
    running: &'static AtomicBool,
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
                match bus_command_tx.send(bus_command) {
                    Ok(_) => {}
                    Err(e) => panic!("Failed to send I3C command to bus: {:?}", e),
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => {
                println!("handle_i3c_socket_connection: Connection reset by client");
                break;
            }
            Err(e) => panic!("Error reading message from socket: {}", e),
        }
        if let Ok(response) = bus_response_rx.recv_timeout(Duration::from_millis(10)) {
            let data_len = response.resp.resp.data_length() as usize;
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
            if data_len > 0 {
                stream.write_all(&response.resp.data[..data_len]).unwrap();
            }
        }
    }
}
