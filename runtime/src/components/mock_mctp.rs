// Licensed under the Apache-2.0 license

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_runtime::mctp::base_protocol::MessageType;
use capsules_runtime::mctp::driver::MCTP_MAX_MESSAGE_SIZE;
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::recv::MCTPRxState;
use capsules_runtime::mctp::send::{MCTPSender, MCTPTxState};
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
use capsules_runtime::test::mctp::MockMctp;
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::time::Alarm;
use kernel::utilities::leasable_buffer::SubSliceMut;

#[macro_export]
macro_rules! mock_mctp_component_static {
    ($A:ty  $(,)?) => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        use capsules_runtime::mctp::base_protocol::MessageType;
        use capsules_runtime::mctp::driver::MCTP_MAX_MESSAGE_SIZE;
        use capsules_runtime::mctp::recv::MCTPRxState;
        use capsules_runtime::mctp::send::MCTPTxState;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
        use capsules_runtime::test::mctp::MockMctp;

        let alarm = kernel::static_buf!(VirtualMuxAlarm<'static, $A>);
        let tx_state = kernel::static_buf!(MCTPTxState<'static, MCTPI3CBinding<'static>, $A>);
        let rx_state = kernel::static_buf!(MCTPRxState<'static, VirtualMuxAlarm<'static, $A>>);
        let rx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let tx_msg_buf = kernel::static_buf!([u8; MCTP_MAX_MESSAGE_SIZE]);
        let msg_types = kernel::static_buf!([MessageType; 1]);
        let mock_mctp = kernel::static_buf!(MockMctp<'static>);
        (
            alarm, tx_state, rx_state, rx_msg_buf, tx_msg_buf, msg_types, mock_mctp,
        )
    }};
}

pub struct MockMctpComponent<A: Alarm<'static> + 'static> {
    mux_mctp: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>, A>,
    mux_alarm: &'static MuxAlarm<'static, A>,
}

impl<A: Alarm<'static>> MockMctpComponent<A> {
    pub fn new(
        mux_mctp: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>, A>,
        mux_alarm: &'static MuxAlarm<'static, A>,
    ) -> Self {
        Self {
            mux_mctp,
            mux_alarm,
        }
    }
}

impl<A: Alarm<'static>> Component for MockMctpComponent<A> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<MCTPTxState<'static, MCTPI3CBinding<'static>, A>>,
        &'static mut MaybeUninit<MCTPRxState<'static, VirtualMuxAlarm<'static, A>>>,
        &'static mut MaybeUninit<[u8; MCTP_MAX_MESSAGE_SIZE]>,
        &'static mut MaybeUninit<[u8; MCTP_MAX_MESSAGE_SIZE]>,
        &'static mut MaybeUninit<[MessageType; 1]>,
        &'static mut MaybeUninit<MockMctp<'static>>,
    );
    type Output = &'static MockMctp<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let rx_msg_buf = static_buffer.3.write([0; MCTP_MAX_MESSAGE_SIZE]);
        let tx_msg_buf = static_buffer.4.write([0; MCTP_MAX_MESSAGE_SIZE]);

        let tx_state = static_buffer.1.write(MCTPTxState::new(self.mux_mctp));

        let msg_types = static_buffer.5.write([MessageType::TestMsgType; 1]);
        let mctp_rx_vitual_alarm = static_buffer.0.write(VirtualMuxAlarm::new(self.mux_alarm));
        let rx_state =
            static_buffer
                .2
                .write(MCTPRxState::new(rx_msg_buf, msg_types, mctp_rx_vitual_alarm));

        let mock_mctp = static_buffer.6.write(MockMctp::new(
            tx_state,
            MessageType::TestMsgType,
            SubSliceMut::new(tx_msg_buf),
        ));

        tx_state.set_client(mock_mctp);
        rx_state.set_client(mock_mctp);
        self.mux_mctp.add_receiver(rx_state);

        mock_mctp
    }
}
