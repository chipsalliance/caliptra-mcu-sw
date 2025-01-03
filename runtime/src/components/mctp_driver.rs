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
//!     mux_mctp,
//!     mctp_spdm_msg_types,
//!     mux_alarm,
//!     )
//!     .finalize(mctp_driver_component_static!());
//! ```

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
use capsules_runtime::mctp::base_protocol::MessageType;
use capsules_runtime::mctp::driver::{MCTPDriver, MCTP_MAX_MESSAGE_SIZE};
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::recv::MCTPRxState;
use capsules_runtime::mctp::send::MCTPSender;
use capsules_runtime::mctp::send::MCTPTxState;
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::hil::time::Alarm;
use kernel::utilities::leasable_buffer::SubSliceMut;

// Setup static space for the objects.
#[macro_export]
macro_rules! mctp_driver_component_static {
    ($A:ty  $(,)?) => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        use capsules_runtime::mctp::driver::MCTPDriver;
        use capsules_runtime::mctp::driver::MCTP_MAX_MESSAGE_SIZE;
        use capsules_runtime::mctp::recv::MCTPRxState;
        use capsules_runtime::mctp::send::MCTPTxState;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;

        let tx_state = kernel::static_buf!(
            MCTPTxState<'static, VirtualMuxAlarm<'static, $A>, MCTPI3CBinding<'static>>
        );
        let rx_state = kernel::static_buf!(MCTPRxState<'static>);
        let rx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let tx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let mctp_driver = kernel::static_buf!(MCTPDriver<'static>);
        (tx_state, rx_state, rx_msg_buf, tx_msg_buf, mctp_driver)
    }};
}

pub struct MCTPDriverComponent<A: Alarm<'static> + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mux_mctp: &'static MuxMCTPDriver<'static, VirtualMuxAlarm<'static, A>, MCTPI3CBinding<'static>>,
    msg_type: MessageType,
}

impl<A: Alarm<'static>> MCTPDriverComponent<A> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mux_mctp: &'static MuxMCTPDriver<
            'static,
            VirtualMuxAlarm<'static, A>,
            MCTPI3CBinding<'static>,
        >,
        msg_type: MessageType,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            mux_mctp,
            msg_type,
        }
    }
}

impl<A: Alarm<'static>> Component for MCTPDriverComponent<A> {
    type StaticInput = (
        &'static mut MaybeUninit<
            MCTPTxState<'static, VirtualMuxAlarm<'static, A>, MCTPI3CBinding<'static>>,
        >,
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

        let tx_state = static_buffer.0.write(MCTPTxState::new(self.mux_mctp));

        let rx_state = static_buffer
            .1
            .write(MCTPRxState::new(rx_msg_buf, self.msg_type));

        let mctp_driver = static_buffer.4.write(MCTPDriver::new(
            tx_state,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
            self.msg_type,
            MCTP_MAX_MESSAGE_SIZE,
            SubSliceMut::new(tx_msg_buf),
        ));

        tx_state.set_client(mctp_driver);
        rx_state.set_client(mctp_driver);
        self.mux_mctp.add_receiver(rx_state);
        mctp_driver
    }
}
