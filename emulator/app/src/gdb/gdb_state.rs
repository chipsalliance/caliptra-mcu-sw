/*++

Licensed under the Apache-2.0 license.

File Name:

    gdb_state.rs

Abstract:

    File contains gdb_state module for Caliptra Emulator supporting non-blocking operation.

--*/

use super::gdb_target::GdbTarget;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::{run_blocking, DisconnectReason, GdbStub, GdbStubError};
use gdbstub::stub::{state_machine::GdbStubStateMachine, SingleThreadStopReason};
use gdbstub::target::Target;
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Wrapper for TcpStream that implements ConnectionExt and provides nonblocking control
struct NonBlockingTcpStream {
    stream: TcpStream,
}

impl NonBlockingTcpStream {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }
}

impl Connection for NonBlockingTcpStream {
    type Error = std::io::Error;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        <TcpStream as std::io::Write>::write_all(&mut self.stream, &[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        <TcpStream as std::io::Write>::write_all(&mut self.stream, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        <TcpStream as std::io::Write>::flush(&mut self.stream)
    }
}

impl ConnectionExt for NonBlockingTcpStream {
    fn read(&mut self) -> Result<u8, Self::Error> {
        let mut buf = [0u8; 1];
        self.stream.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        // TcpStream doesn't support peek, so we'll just return None
        Ok(None)
    }
}

struct GdbEventLoop {}

// The `run_blocking::BlockingEventLoop` groups together various callbacks
// the `GdbStub::run_blocking` event loop requires you to implement.
impl run_blocking::BlockingEventLoop for GdbEventLoop {
    type Target = GdbTarget;
    type Connection = NonBlockingTcpStream;

    // or MultiThreadStopReason on multi threaded targets
    type StopReason = SingleThreadStopReason<u32>;

    // Invoked immediately after the target's `resume` method has been
    // called. The implementation should block until either the target
    // reports a stop reason, or if new data was sent over the connection.
    fn wait_for_stop_reason(
        target: &mut GdbTarget,
        _conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<SingleThreadStopReason<u32>>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        // Execute Target with responsive interrupt checking
        let stop_reason = target.run_responsive();

        // Report Stop Reason
        Ok(run_blocking::Event::TargetStopped(stop_reason))
    }

    // Invoked when the GDB client sends a Ctrl-C interrupt.
    fn on_interrupt(
        target: &mut GdbTarget,
    ) -> Result<Option<SingleThreadStopReason<u32>>, <GdbTarget as Target>::Error> {
        // Signal the target to interrupt its execution
        println!("GDB requested an interrupt (Ctrl+C)");
        target.request_interrupt();

        // Immediately return a SIGINT to stop execution
        Ok(Some(SingleThreadStopReason::Signal(
            gdbstub::common::Signal::SIGINT,
        )))
    }
}

/// GDB Server that can be controlled from external threads
/// This provides a way to control GDB from C bindings without moving the emulator to another thread
pub struct ControlledGdbServer {
    state_machine: Option<GdbStubStateMachine<'static, GdbTarget, NonBlockingTcpStream>>,
    interrupt_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    listener: Option<TcpListener>,
    port: u16,
}

impl ControlledGdbServer {
    /// Create a new controlled GDB server that listens on the specified port
    pub fn new(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let sockaddr = format!("localhost:{}", port);
        let listener = TcpListener::bind(&sockaddr)?;
        listener.set_nonblocking(true)?;

        Ok(ControlledGdbServer {
            state_machine: None,
            interrupt_flag: Arc::new(AtomicBool::new(false)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            listener: Some(listener),
            port,
        })
    }

    /// Check for and accept a GDB connection (non-blocking)
    pub fn try_accept_connection(
        &mut self,
        cpu: &mut GdbTarget,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if self.state_machine.is_some() {
            return Ok(true); // Already connected
        }

        if let Some(ref listener) = self.listener {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    stream.set_nonblocking(false)?;

                    // Set up the state machine
                    let connection = NonBlockingTcpStream::new(stream);
                    let gdb = GdbStub::new(connection);
                    self.state_machine = Some(gdb.run_state_machine(cpu)?);

                    // Store the interrupt and stop flags in the CPU
                    cpu.set_interrupt_flag(self.interrupt_flag.clone());
                    cpu.set_stop_flag(self.stop_flag.clone());

                    self.listener = None; // Close the listener
                    Ok(true)
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Ok(false) // No connection yet
                }
                Err(e) => Err(Box::new(e)),
            }
        } else {
            Ok(self.state_machine.is_some())
        }
    }

    /// Process GDB messages (blocking when in break state)
    pub fn process_messages(
        &mut self,
        cpu: &mut GdbTarget,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(state_machine) = self.state_machine.take() {
            match state_machine {
                GdbStubStateMachine::Idle(mut gdb) => {
                    // In Idle state, GDB is waiting for commands and execution is stopped
                    // This state should block until a complete command is received

                    // Set connection to blocking to wait for GDB commands
                    gdb.borrow_conn()
                        .set_nonblocking(false)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

                    // Read a single byte and process it
                    match gdb.borrow_conn().read() {
                        Ok(byte) => {
                            // Process the byte - this may transition to a new state
                            match gdb.incoming_data(cpu, byte) {
                                Ok(new_state) => {
                                    self.state_machine = Some(new_state);
                                }
                                Err(e) => return Err(Box::new(e)),
                            }
                        }
                        Err(e) => return Err(Box::new(e)),
                    }
                }

                GdbStubStateMachine::Disconnected(_) => {
                    return Ok(false); // Connection closed
                }

                GdbStubStateMachine::CtrlCInterrupt(gdb) => {
                    cpu.request_interrupt();
                    let stop_reason = Some(SingleThreadStopReason::Signal(
                        gdbstub::common::Signal::SIGINT,
                    ));
                    self.state_machine = Some(gdb.interrupt_handled(cpu, stop_reason)?);
                }

                GdbStubStateMachine::Running(mut gdb) => {
                    // In Running state, we check for incoming data (Ctrl+C, etc.) - non-blocking
                    // The C code is responsible for calling emulator_step() and checking for stop conditions
                    gdb.borrow_conn()
                        .set_nonblocking(true)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

                    match gdb.borrow_conn().read() {
                        Ok(byte) => {
                            // Received data (likely Ctrl+C), switch back to blocking and process
                            gdb.borrow_conn()
                                .set_nonblocking(false)
                                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                            self.state_machine = Some(gdb.incoming_data(cpu, byte)?);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // No incoming data - restore running state and continue
                            gdb.borrow_conn()
                                .set_nonblocking(false)
                                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                            self.state_machine = Some(GdbStubStateMachine::Running(gdb));
                        }
                        Err(e) => return Err(Box::new(e)),
                    }
                }
            }
        }

        Ok(true) // Still connected
    }

    /// Send an interrupt signal to the GDB target
    pub fn interrupt(&self) {
        self.interrupt_flag.store(true, Ordering::Relaxed);
    }

    /// Stop the GDB server
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Check if the GDB server has an active connection
    pub fn is_connected(&self) -> bool {
        self.state_machine.is_some()
    }

    /// Check if GDB is currently in idle state (suspended due to breakpoint/interrupt)
    pub fn is_idle(&self) -> bool {
        if let Some(ref state_machine) = self.state_machine {
            matches!(state_machine, GdbStubStateMachine::Idle(_))
        } else {
            false
        }
    }

    /// Check if GDB is currently in running state (emulator executing)
    pub fn is_running(&self) -> bool {
        if let Some(ref state_machine) = self.state_machine {
            matches!(state_machine, GdbStubStateMachine::Running(_))
        } else {
            false
        }
    }

    /// Report a stop condition to GDB (called by C code after stepping)
    /// This should be called when the C code detects a stop condition after calling emulator_step()
    pub fn report_stop(
        &mut self,
        cpu: &mut GdbTarget,
        stop_reason: gdbstub::stub::SingleThreadStopReason<u32>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(state_machine) = self.state_machine.take() {
            match state_machine {
                GdbStubStateMachine::Running(gdb) => {
                    // Report the stop and transition to Idle state
                    // This will cause the next process_messages call to block and wait for user commands
                    self.state_machine = Some(gdb.report_stop(cpu, stop_reason)?);
                    Ok(true)
                }
                other => {
                    // If not in Running state, just restore the state machine
                    self.state_machine = Some(other);
                    Ok(true)
                }
            }
        } else {
            Ok(false) // No connection
        }
    }

    /// Get the port the server is listening on
    pub fn port(&self) -> u16 {
        self.port
    }
}

// Original blocking interface for compatibility
pub fn wait_for_gdb_run(cpu: &mut GdbTarget, port: u16) {
    // Create Socket
    let sockaddr = format!("localhost:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
    let sock = TcpListener::bind(sockaddr).unwrap();
    let (stream, addr) = sock.accept().unwrap();
    eprintln!("Debugger connected from {}", addr);

    // Create Connection
    let connection = NonBlockingTcpStream::new(stream);

    // Instantiate GdbStub
    let gdb = GdbStub::new(connection);

    // Execute GDB until a disconnect event
    match gdb.run_blocking::<GdbEventLoop>(cpu) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                println!("Client disconnected")
            }
            DisconnectReason::TargetExited(code) => {
                println!("Target exited with code {}", code)
            }
            DisconnectReason::TargetTerminated(sig) => {
                println!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => println!("GDB sent a kill command"),
        },
        Err(GdbStubError::TargetError(e)) => {
            println!("target encountered a fatal error: {}", e)
        }
        Err(e) => {
            println!("gdbstub encountered a fatal error: {}", e)
        }
    }
}
