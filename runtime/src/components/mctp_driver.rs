// Licensed under the Apache-2.0 license

//! Component for initializing the MCTP driver.
//!
//! This module provides MCTPDriverComponent, which sets up the syscall driver for MCTP,
//! enabling user space applications to send and receive MCTP messages.
//!
//! Each application that handles specific MCTP message types will utilize the MCTP driver
//! instantiated for that particular message type.
//!
//! Usage
//! -----
//! ```rust
//! let spdm_mctp_driver = MCTPDriverComponent::new(
//!     board_kernel,
//!     capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM,
//!     mctp_mux,
//!     mctp_spdm_msg_types,
//!     )
//!     .finalize(mctp_driver_component_static!());
//! ```

use capsules_runtime::mctp::base_protocol::MessageType;
use capsules_runtime::mctp::driver::{MCTPDriver, MCTP_MAX_MESSAGE_SIZE};
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::recv::MCTPRxState;
use capsules_runtime::mctp::send::MCTPSender;
use capsules_runtime::mctp::send::MCTPTxState;
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;

use kernel::capabilities;
use kernel::component::Component;
use kernel::utilities::leasable_buffer::SubSliceMut;

use core::mem::MaybeUninit;

// Setup static space for the objects.
#[macro_export]
macro_rules! mctp_driver_component_static {
    () => {{
        use capsules_runtime::mctp::driver::MCTPDriver;
        use capsules_runtime::mctp::driver::MCTP_MAX_MESSAGE_SIZE;
        use capsules_runtime::mctp::recv::MCTPRxState;
        use capsules_runtime::mctp::send::MCTPTxState;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;

        let tx_state = kernel::static_buf!(MCTPTxState<'static, MCTPI3CBinding<'static>>);
        let rx_state = kernel::static_buf!(MCTPRxState<'static>);
        let rx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let tx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let mctp_driver = kernel::static_buf!(MCTPDriver<'static>);
        (tx_state, rx_state, rx_msg_buf, tx_msg_buf, mctp_driver)
    }};
}

pub struct MCTPDriverComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mctp_mux: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>>,
    msg_types: &'static [MessageType],
}

impl MCTPDriverComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mctp_mux: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>>,
        msg_types: &'static [MessageType],
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            mctp_mux,
            msg_types,
        }
    }
}

impl Component for MCTPDriverComponent {
    type StaticInput = (
        &'static mut MaybeUninit<MCTPTxState<'static, MCTPI3CBinding<'static>>>,
        &'static mut MaybeUninit<MCTPRxState<'static>>,
        &'static mut MaybeUninit<[u8; MCTP_MAX_MESSAGE_SIZE]>,
        &'static mut MaybeUninit<[u8; MCTP_MAX_MESSAGE_SIZE]>,
        &'static mut MaybeUninit<MCTPDriver<'static>>,
    );
    type Output = &'static MCTPDriver<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = kernel::create_capability!(capabilities::MemoryAllocationCapability);

        let rx_msg_buf = static_buffer.2.write([0; MCTP_MAX_MESSAGE_SIZE]);
        let tx_msg_buf = static_buffer.3.write([0; MCTP_MAX_MESSAGE_SIZE]);

        let tx_state = static_buffer.0.write(MCTPTxState::new(self.mctp_mux));
        let rx_state = static_buffer
            .1
            .write(MCTPRxState::new(rx_msg_buf, self.msg_types));

        let mctp_driver = static_buffer.4.write(MCTPDriver::new(
            tx_state,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
            self.msg_types,
            MCTP_MAX_MESSAGE_SIZE,
            SubSliceMut::new(tx_msg_buf),
        ));

        tx_state.set_client(mctp_driver);
        rx_state.set_client(mctp_driver);
        self.mctp_mux.add_receiver(rx_state);
        mctp_driver
    }
}
