// Licensed under the Apache-2.0 license

//! Component for initializing the MCTP mux.
//!
//! This provides MCTPMuxComponent, which initializes the MCTP mux.
//!
//! Usage
//! -----
//! ```ignore
//! use mcu_components::mctp_mux_component_static;
//! use kernel::component::Component;
//! use mcu_tock_veer::timers::InternalTimers;
//! let mux_mctp = mcu_components::mux_mctp::MCTPMuxComponent::new(
//!    i3c,
//!    mux_alarm)
//! .finalize(mctp_mux_component_static!(InternalTimers, MCTPI3CBinding));
//! ```
//!

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::transport_binding::{MCTPI3CBinding, MCTPTransportBinding};
use core::mem::MaybeUninit;
use i3c_driver::core::MAX_READ_WRITE_SIZE;
use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::time::Alarm;

// Setup static space for the objects.
#[macro_export]
macro_rules! mctp_mux_component_static {
    ($A:ty, $T:ty $(,)?) => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        use capsules_runtime::mctp::mux::MuxMCTPDriver;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
        use i3c_driver::core::MAX_READ_WRITE_SIZE;

        let alarm = kernel::static_buf!(VirtualMuxAlarm<'static, $A>);
        let tx_buffer = kernel::static_buf!([u8; MAX_READ_WRITE_SIZE]);
        let rx_buffer = kernel::static_buf!([u8; MAX_READ_WRITE_SIZE]);
        let mctp_i3c_binding = kernel::static_buf!(MCTPI3CBinding<'static>);
        let mux_mctp_driver =
            kernel::static_buf!(MuxMCTPDriver<'static, VirtualMuxAlarm<'static, $A>, $T>);
        (
            alarm,
            tx_buffer,
            rx_buffer,
            mctp_i3c_binding,
            mux_mctp_driver,
        )
    }};
}

pub struct MCTPMuxComponent<A: Alarm<'static> + 'static> {
    i3c_target: &'static dyn i3c_driver::hil::I3CTarget<'static>,
    mux_alarm: &'static MuxAlarm<'static, A>,
}

impl<A: Alarm<'static>> MCTPMuxComponent<A> {
    pub fn new(
        i3c_target: &'static dyn i3c_driver::hil::I3CTarget,
        mux_alarm: &'static MuxAlarm<'static, A>,
    ) -> Self {
        Self {
            i3c_target,
            mux_alarm,
        }
    }
}

impl<A: Alarm<'static>> Component for MCTPMuxComponent<A> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<[u8; MAX_READ_WRITE_SIZE]>,
        &'static mut MaybeUninit<[u8; MAX_READ_WRITE_SIZE]>,
        &'static mut MaybeUninit<MCTPI3CBinding<'static>>,
        &'static mut MaybeUninit<
            MuxMCTPDriver<'static, VirtualMuxAlarm<'static, A>, MCTPI3CBinding<'static>>,
        >,
    );
    type Output =
        &'static MuxMCTPDriver<'static, VirtualMuxAlarm<'static, A>, MCTPI3CBinding<'static>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let mctp_device = static_buffer.3.write(MCTPI3CBinding::new(self.i3c_target));
        mctp_device.setup_mctp_i3c();
        self.i3c_target.set_tx_client(mctp_device);
        self.i3c_target.set_rx_client(mctp_device);

        let mtu = mctp_device.get_mtu_size();
        let tx_pkt_buffer = static_buffer.1.write([0; MAX_READ_WRITE_SIZE]);
        let rx_pkt_buffer = static_buffer.2.write([0; MAX_READ_WRITE_SIZE]);
        let local_eid = 0; // could be a default value or 0 until dynamically assigned

        let mux_mctp_alarm = static_buffer.0.write(VirtualMuxAlarm::new(self.mux_alarm));
        mux_mctp_alarm.setup();

        let mux_mctp_driver = static_buffer.4.write(MuxMCTPDriver::new(
            mctp_device,
            local_eid,
            mtu,
            tx_pkt_buffer,
            rx_pkt_buffer,
            mux_mctp_alarm,
        ));

        mctp_device.set_tx_client(mux_mctp_driver);
        mctp_device.set_rx_client(mux_mctp_driver);

        mux_mctp_driver.register();
        mux_mctp_driver
    }
}
