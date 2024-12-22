// Licensed under the Apache-2.0 license

//! Component for initializing the MCTP mux.
//!
//! This provides MCTPMuxComponent, which initializes the MCTP mux.
//!
//! Usage
//! -----
//! ```rust
//! let mux_mctp = MCTPMuxComponent::new(&peripherals.i3c).finalize(
//!    mctp_mux_component_static!());
//! ```
//!

use crate::timers::InternalTimers;
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::transport_binding::{MCTPI3CBinding, MCTPTransportBinding};
use core::mem::MaybeUninit;
use i3c_driver::core::MAX_READ_WRITE_SIZE;
use kernel::component::Component;

// Setup static space for the objects.
#[macro_export]
macro_rules! mctp_mux_component_static {
    ($T:ty, $A:ty $(,)?) => {{
        use capsules_runtime::mctp::mux::MuxMCTPDriver;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
        use i3c_driver::core::MAX_READ_WRITE_SIZE;

        let tx_buffer = kernel::static_buf!([u8; MAX_READ_WRITE_SIZE]);
        let rx_buffer = kernel::static_buf!([u8; MAX_READ_WRITE_SIZE]);
        let mctp_i3c_binding = kernel::static_buf!(MCTPI3CBinding<'static>);
        let mux_mctp_driver = kernel::static_buf!(MuxMCTPDriver<'static, $T, $A>);
        (tx_buffer, rx_buffer, mctp_i3c_binding, mux_mctp_driver)
    }};
}

pub struct MCTPMuxComponent {
    i3c_target: &'static dyn i3c_driver::hil::I3CTarget<'static>,
}

impl MCTPMuxComponent {
    pub fn new(i3c_target: &'static dyn i3c_driver::hil::I3CTarget) -> Self {
        Self {
            i3c_target: i3c_target,
        }
    }
}

impl Component for MCTPMuxComponent {
    type StaticInput = (
        &'static mut MaybeUninit<[u8; MAX_READ_WRITE_SIZE]>,
        &'static mut MaybeUninit<[u8; MAX_READ_WRITE_SIZE]>,
        &'static mut MaybeUninit<MCTPI3CBinding<'static>>,
        &'static mut MaybeUninit<MuxMCTPDriver<'static, MCTPI3CBinding<'static>, InternalTimers<'static>>>,
    );
    type Output = &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>, InternalTimers<'static>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let mctp_device = static_buffer.2.write(MCTPI3CBinding::new(self.i3c_target));
        mctp_device.setup_mctp_i3c();
        self.i3c_target.set_tx_client(mctp_device);
        self.i3c_target.set_rx_client(mctp_device);

        let mtu = mctp_device.get_mtu_size();
        let tx_pkt_buffer = static_buffer.0.write([0; MAX_READ_WRITE_SIZE]);
        let rx_pkt_buffer = static_buffer.1.write([0; MAX_READ_WRITE_SIZE]);
        let local_eid = 0; // could be a default value or 0 until dynamically assigned

        let mux_mctp_driver = static_buffer.3.write(MuxMCTPDriver::new(
            mctp_device,
            local_eid,
            mtu,
            tx_pkt_buffer,
            rx_pkt_buffer,
        ));

        mctp_device.set_tx_client(mux_mctp_driver);
        mctp_device.set_rx_client(mux_mctp_driver);

        mux_mctp_driver
    }
}
