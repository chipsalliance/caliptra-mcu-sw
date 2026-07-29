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
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::vec;
use zerocopy::{transmute, FromBytes, IntoBytes};

pub const CRC8_SMBUS: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);

pub fn start_i3c_socket(port: u16) -> (Receiver<I3cBusCommand>, Sender<I3cBusResponse>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .expect("Failed to bind TCP socket for port");

    let (bus_command_tx, bus_command_rx) = mpsc::channel::<I3cBusCommand>();
    let (bus_response_tx, bus_response_rx) = mpsc::channel::<I3cBusResponse>();
    crate::spawn_with_emulator_state(move || {
        handle_i3c_socket_loop(listener, bus_response_rx, bus_command_tx)
    });

    (bus_command_rx, bus_response_tx)
}

pub fn handle_i3c_socket_loop(
    listener: TcpListener,
    mut bus_response_rx: Receiver<I3cBusResponse>,
    mut bus_command_tx: Sender<I3cBusCommand>,
) {
    listener
        .set_nonblocking(true)
        .expect("Could not set non-blocking");
    while crate::is_emulator_running() {
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("Accepting I3C socket connection from {:?}", addr);
                handle_i3c_socket_connection(
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

/// Returns true when an I/O error indicates that the TCP client has gone away.
///
/// When the client disconnects (cleanly via EOF, or abruptly via a reset/abort/
/// broken pipe) the connection can no longer be used. The connection handler
/// should stop and return to the accept loop instead of panicking, which would
/// kill the server thread and prevent any new connections from being accepted.
fn is_client_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

fn handle_i3c_socket_connection(
    mut stream: TcpStream,
    _addr: SocketAddr,
    bus_response_rx: &mut Receiver<I3cBusResponse>,
    bus_command_tx: &mut Sender<I3cBusCommand>,
) {
    let stream = &mut stream;
    stream.set_nonblocking(true).unwrap();

    while crate::is_emulator_running() {
        // try reading from TCP socket (non-blocking)
        let mut incoming_header_bytes = [0u8; 9];
        match stream.read_exact(&mut incoming_header_bytes) {
            Ok(()) => {
                let incoming_header: IncomingHeader = transmute!(incoming_header_bytes);
                let cmd: I3cTcriCommand = incoming_header.command.try_into().unwrap();
                // For read commands (rnw=1), data_length specifies how much to
                // read FROM the target — no payload follows on the socket.
                let is_read = matches!(&cmd, I3cTcriCommand::Regular(r) if r.rnw() == 1);
                let wire_data_len = if is_read { 0 } else { cmd.data_len() };
                let mut data = vec![0u8; wire_data_len];
                stream.set_nonblocking(false).unwrap();
                let payload_result = stream.read_exact(&mut data);
                if let Err(e) = payload_result {
                    if is_client_disconnect(&e) {
                        println!(
                            "handle_i3c_socket_connection: Client disconnected while reading payload ({}); returning to accept loop",
                            e.kind()
                        );
                        break;
                    }
                    panic!("Error reading message from socket: {}", e);
                }
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
            Err(ref e) if is_client_disconnect(e) => {
                println!(
                    "handle_i3c_socket_connection: Client disconnected while reading header ({}); returning to accept loop",
                    e.kind()
                );
                break;
            }
            Err(e) => panic!("Error reading message from socket: {}", e),
        }

        // Try receiving from bus response channel (non-blocking)
        match bus_response_rx.try_recv() {
            Ok(response) => {
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
                let write_result = stream.write_all(&header_bytes).and_then(|()| {
                    if data_len > 0 {
                        stream.write_all(&response.resp.data[..data_len])
                    } else {
                        Ok(())
                    }
                });
                if let Err(e) = write_result {
                    if is_client_disconnect(&e) {
                        println!(
                            "handle_i3c_socket_connection: Client disconnected while writing response ({}); returning to accept loop",
                            e.kind()
                        );
                        break;
                    }
                    panic!("Error writing message to socket: {}", e);
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // Brief sleep to avoid busy-spinning while still being responsive.
                // Using thread::sleep instead of condvar to avoid depending on
                // emulator tick notifications (which may stall during warm reboot).
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i3c::ReguDataTransferCommand;
    use crate::{
        init_emulator_state, set_emulator_running, spawn_with_emulator_state, EmulatorState,
    };
    use std::time::Duration;

    // Build the 9-byte on-wire header for a private write command that promises
    // `data_length` payload bytes to follow (rnw = 0, Regular transfer).
    fn private_write_header(to_addr: u8, data_length: u16) -> [u8; 9] {
        let mut cmd = ReguDataTransferCommand::read_from_bytes(&[0u8; 8]).unwrap();
        cmd.set_rnw(0);
        cmd.set_data_length(data_length);
        let command: [u32; 2] = transmute!(cmd);
        let header = IncomingHeader { to_addr, command };
        transmute!(header)
    }

    // Spawn the socket server loop on an ephemeral port. Returns the bound port,
    // the server join handle, and the channel ends that must be kept alive for
    // the duration of the test (dropping them would disconnect the server's
    // channels).
    fn spawn_server() -> (
        u16,
        std::thread::JoinHandle<()>,
        Receiver<I3cBusCommand>,
        Sender<I3cBusResponse>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (bus_command_tx, bus_command_rx) = mpsc::channel::<I3cBusCommand>();
        let (bus_response_tx, bus_response_rx) = mpsc::channel::<I3cBusResponse>();
        let handle = spawn_with_emulator_state(move || {
            handle_i3c_socket_loop(listener, bus_response_rx, bus_command_tx);
        });
        (port, handle, bus_command_rx, bus_response_tx)
    }

    // A client that connects and then disconnects while idle must not crash the
    // server thread: it should return to the accept loop and keep serving.
    #[test]
    fn server_survives_client_disconnect_before_sending() {
        init_emulator_state(EmulatorState::new_arc());
        let (port, server, _cmd_rx, _resp_tx) = spawn_server();

        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        std::thread::sleep(Duration::from_millis(50));

        let reconnect = TcpStream::connect(("127.0.0.1", port));
        assert!(
            reconnect.is_ok(),
            "server should accept new connections after a client disconnect"
        );
        drop(reconnect);

        set_emulator_running(false);
        server
            .join()
            .expect("server thread must not panic when a client disconnects");
    }

    // Regression test for issue #1137: a client that disconnects after sending a
    // command header but before the promised payload must not panic the server.
    #[test]
    fn server_survives_client_disconnect_mid_message() {
        init_emulator_state(EmulatorState::new_arc());
        let (port, server, _cmd_rx, _resp_tx) = spawn_server();

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(&private_write_header(0x08, 4)).unwrap();
        client.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        std::thread::sleep(Duration::from_millis(50));

        let reconnect = TcpStream::connect(("127.0.0.1", port));
        assert!(
            reconnect.is_ok(),
            "server should accept new connections after a mid-message disconnect"
        );
        drop(reconnect);

        set_emulator_running(false);
        server
            .join()
            .expect("server thread must not panic on mid-message client disconnect");
    }
}
