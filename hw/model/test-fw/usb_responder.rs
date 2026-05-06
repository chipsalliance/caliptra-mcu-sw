// Licensed under the Apache-2.0 license

//! Bare-metal test firmware that echoes USB packets back to the host.
//!
//! Initialises EP 0 for SETUP/OUT/IN, pushes available buffers, sets
//! `usbctrl.enable`, then loops: on each received packet it reads the
//! payload from the packet buffer, writes it into a response buffer,
//! configures `configin[0]` with that buffer, and re-arms reception.

#![no_main]
#![no_std]

use registers_generated::usbdev;
use registers_generated::usbdev::bits::*;
use tock_registers::interfaces::{Readable, Writeable};

extern crate mcu_rom_common;

const NUM_BUFFERS: u32 = 4;

fn run() -> ! {
    let usb = unsafe { &*(usbdev::USBDEV_ADDR as *const usbdev::regs::Usbdev) };

    // Enable EP 0 for OUT and IN
    usb.ep_out_enable.set(0x001);
    usb.ep_in_enable.set(0x001);
    usb.rxenable_setup.set(0x001);
    usb.rxenable_out.set(0x001);

    // Push available buffers: 0 for setup, 1..NUM_BUFFERS for out
    usb.avsetupbuffer.set(0);
    for buf_id in 1..NUM_BUFFERS {
        usb.avoutbuffer.set(buf_id);
    }

    // Signal to the host that we are ready
    usb.usbctrl.write(Usbctrl::Enable::SET);

    // Track the next free buffer for responses
    let mut next_response_buf: u32 = NUM_BUFFERS;

    loop {
        // Poll for a received packet
        if !usb.intr_state.is_set(IntrState::PktReceived) {
            continue;
        }

        let rxfifo = usb.rxfifo.extract();
        let rx_buf = rxfifo.read(Rxfifo::Buffer);
        let rx_size = rxfifo.read(Rxfifo::Size);
        let rx_is_setup = rxfifo.is_set(Rxfifo::Setup);

        // Read the received payload from the packet buffer
        let rx_word_base = (rx_buf * 16) as usize;
        let num_words = ((rx_size as usize) + 3) / 4;
        let resp_buf = next_response_buf;
        let resp_word_base = (resp_buf * 16) as usize;

        // Copy received data into the response buffer
        for i in 0..num_words {
            let word = usb.buffer[rx_word_base + i].get();
            usb.buffer[resp_word_base + i].set(word);
        }

        // Configure configin[0] to send the response
        usb.configin_0[0].write(
            Configin0::Buffer0.val(resp_buf) + Configin0::Size0.val(rx_size) + Configin0::Rdy0::SET,
        );

        // Clear pkt_received interrupt (W1C)
        usb.intr_state.set(IntrState::PktReceived::SET.value);

        // Re-arm: push the consumed rx buffer back as an available buffer
        if rx_is_setup {
            usb.avsetupbuffer.set(rx_buf);
        } else {
            usb.avoutbuffer.set(rx_buf);
        }

        // Advance response buffer (wrap around a small pool)
        next_response_buf = if next_response_buf >= 31 {
            NUM_BUFFERS
        } else {
            next_response_buf + 1
        };
    }
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
