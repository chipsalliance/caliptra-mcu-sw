// Licensed under the Apache-2.0 license

use capsules_runtime::mctp::base_protocol::MessageType;
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::recv::MCTPRxState;
use capsules_runtime::mctp::send::{MCTPSender, MCTPTxState};
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
use capsules_runtime::test::mctp::{MockMctp, MCTP_TEST_MSG_SIZE};

use kernel::component::Component;
use kernel::utilities::leasable_buffer::SubSliceMut;

use core::mem::MaybeUninit;

#[macro_export]
macro_rules! mock_mctp_component_static {
    () => {{
        use capsules_runtime::mctp::base_protocol::MessageType;
        use capsules_runtime::mctp::recv::MCTPRxState;
        use capsules_runtime::mctp::send::MCTPTxState;
        use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
        use capsules_runtime::test::mctp::MockMctp;
        use capsules_runtime::test::mctp::MCTP_TEST_MSG_SIZE;

        let tx_state = kernel::static_buf!(MCTPTxState<'static, MCTPI3CBinding<'static>>);
        let rx_state = kernel::static_buf!(MCTPRxState<'static>);
        let rx_msg_buf = kernel::static_buf!([u8; MCTP_TEST_MSG_SIZE]);
        let tx_msg_buf = kernel::static_buf!([u8; MCTP_TEST_MSG_SIZE]);
        let msg_types = kernel::static_buf!([MessageType; 1]);
        let mock_mctp = kernel::static_buf!(MockMctp<'static>);
        (
            tx_state, rx_state, rx_msg_buf, tx_msg_buf, msg_types, mock_mctp,
        )
    }};
}

pub struct MockMctpComponent {
    mctp_mux: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>>,
    // msg_types: &'static [u8],
}

impl MockMctpComponent {
    pub fn new(mctp_mux: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>>) -> Self {
        Self { mctp_mux }
    }
}

impl Component for MockMctpComponent {
    type StaticInput = (
        &'static mut MaybeUninit<MCTPTxState<'static, MCTPI3CBinding<'static>>>,
        &'static mut MaybeUninit<MCTPRxState<'static>>,
        &'static mut MaybeUninit<[u8; MCTP_TEST_MSG_SIZE]>,
        &'static mut MaybeUninit<[u8; MCTP_TEST_MSG_SIZE]>,
        &'static mut MaybeUninit<[MessageType; 1]>,
        &'static mut MaybeUninit<MockMctp<'static>>,
    );
    type Output = &'static MockMctp<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let rx_msg_buf = static_buffer.2.write([0; MCTP_TEST_MSG_SIZE]);
        let tx_msg_buf = static_buffer.3.write([0; MCTP_TEST_MSG_SIZE]);

        let tx_state = static_buffer.0.write(MCTPTxState::new(self.mctp_mux));

        let msg_types = static_buffer.4.write([MessageType::TestMsgType; 1]);

        let rx_state = static_buffer
            .1
            .write(MCTPRxState::new(rx_msg_buf, msg_types));

        let mock_mctp = static_buffer.5.write(MockMctp::new(
            tx_state,
            MessageType::TestMsgType,
            SubSliceMut::new(tx_msg_buf),
        ));

        tx_state.set_client(mock_mctp);
        rx_state.set_client(mock_mctp);
        self.mctp_mux.add_receiver(rx_state);

        mock_mctp
    }
}
