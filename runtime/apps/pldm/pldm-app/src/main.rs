// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use embassy_executor::Spawner;
use libtock_console::Console;
use libtock_platform::Syscalls;
use pldm_common::message::firmware_update::request_fw_data::RequestFirmwareDataRequest;
use pldm_lib::{daemon::PldmService, error::MsgHandlerError, transport::MctpTransport};
use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmFailureResponse, PldmMsgHeader, PldmMsgType};
use pldm_common::codec::PldmCodec;
use libtockasync::{self, start_async, TockExecutor};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::signal::Signal;

#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let console = fake::Console::new();
    kernel.add_driver(&console);
    kernel
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_runtime::TockSyscalls>().await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_unittest::fake::Syscalls>().await;
}


static SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "PLDM_APP: Hello PLDM async world!").unwrap();

    if cfg!(any(
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
    )) {

        let mut executor1 = TockExecutor::new();
        let executor1: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor1) };
        executor1.spawner().spawn(pldm_responder_task()).unwrap();


        let mut executor2 = TockExecutor::new();
        let executor2: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor2) };
        executor2.spawner().spawn(pldm_initiator_task()).unwrap();


        loop {
            executor1.poll();
            executor2.poll();
        }

    } 
    

}


use libsyscall_caliptra::mctp::driver_num;


#[embassy_executor::task]
pub async fn pldm_initiator_task() 
{
    pldm_initiator::<libtock_runtime::TockSyscalls>().await;
}

#[embassy_executor::task]
pub async fn pldm_responder_task() 
{
    pldm_responder::<libtock_runtime::TockSyscalls>().await;
}


pub async fn pldm_responder<S:Syscalls>() {
    let mut transport: MctpTransport<S> = MctpTransport::new(driver_num::MCTP_PLDM);
    let mut msg_buffer = [0; 1024];
    let mut is_responder_mode = true;
    writeln!(Console::<S>::writer(), "Reponder: Running").unwrap();
    loop {
        match transport.receive_request(&mut msg_buffer).await {
            Ok(_) => {
                writeln!(Console::<S>::writer(), "Reponder: Received request").unwrap();
                let pldm_payload = &mut msg_buffer[1..];
                let header = PldmMsgHeader::decode(pldm_payload).map_err(MsgHandlerError::Codec).unwrap();
                let resp = PldmFailureResponse {
                    hdr: header.into_response(),
                    completion_code : PldmBaseCompletionCode::UnsupportedPldmCmd as u8,
                };
                let sz  = resp.encode(pldm_payload).map_err(MsgHandlerError::Codec).unwrap();

                transport.send_response(&msg_buffer[0..=sz]).await.unwrap();

                writeln!(Console::<S>::writer(), "Reponder: Activate initiator").unwrap();

                if is_responder_mode {
                    // switch to initiator mode
                    SIGNAL.signal(());
                    is_responder_mode = false;
                }
            }
            Err(e) => {
                // Handle error
                writeln!(Console::<S>::writer(), "Reponder: Error receiving request: {:?}", e).unwrap();
            }
        }
    }
}



pub async fn pldm_initiator<S:Syscalls>() 
{
    let mut transport: MctpTransport<S> = MctpTransport::new(driver_num::MCTP_PLDM);
    let mut msg_buffer = [0; 1024];
    msg_buffer[0] = 0x1;
    writeln!(Console::<S>::writer(), "Initiator: Running").unwrap();
    loop {

        writeln!(Console::<S>::writer(), "Initiator: Waiting to be activated").unwrap();
        SIGNAL.wait().await;
        writeln!(Console::<S>::writer(), "Initiator: activated").unwrap();
        

        let pldm_payload = &mut msg_buffer[1..];

        let request =
            RequestFirmwareDataRequest::new(1, PldmMsgType::Request, 0, 256);

        let sz = request.encode(pldm_payload).map_err(MsgHandlerError::Codec).unwrap();

        transport.send_request(0,&msg_buffer[0..=sz]).await.unwrap();


        match transport.receive_response(&mut msg_buffer).await {
            Ok(_) => {
                writeln!(Console::<S>::writer(), "Initiator: Received response").unwrap();

            }
            Err(e) => {
                // Handle error
                writeln!(Console::<S>::writer(), "Initiator: Error response request: {:?}", e).unwrap();
            }
        }
    }
}