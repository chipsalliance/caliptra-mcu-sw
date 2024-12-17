use crate::components::mock_mctp::MockMctpComponent;
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
use capsules_runtime::test::mctp::MockMctp;
use capsules_runtime::test::mctp::TestClient;

use core::fmt::Write;
use romtime::println;

use kernel::component::Component;
use kernel::static_init;

pub fn test_mctp_send_loopback(
    mctp_mux: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>>,
) -> Option<u32> {
    // set local EID here if needed.
    let mock_mctp =
        unsafe { MockMctpComponent::new(mctp_mux).finalize(crate::mock_mctp_component_static!()) };
    let mctp_tester = unsafe { static_init!(TestMctp<'static>, TestMctp::new(mock_mctp)) };
    mock_mctp.set_test_client(mctp_tester);
    mock_mctp.run_send_loopback_test();
    None
}

// macro_rules! mctp_tester_init {
//     ($M:expr) => {{
//         use crate::components::mock_mctp::MockMctpComponent;
//         use capsules_runtime::mctp::test::TestMctp;

//         let mctp_msg_buf = static_init!([u8; MCTP_MAX_MESSAGE_SIZE], [0; MCTP_MAX_MESSAGE_SIZE]);
//         let msg_types = static_init!([u8; 1], [MCTP_TEST_MSG_TYPE]);
//         let mock_mctp_driver = MockMctpComponent::new($M, msg_types).finalize(mock_mctp_component_static!());
//         let mctp_tester = TestMctp::new(mock_mctp_driver, mctp_msg_buf);
//         mock_mctp_driver.set_rx_client(&mctp_tester);
//         mock_mctp_driver.set_tx_client(&mctp_tester);
//         mctp_tester
//     }};
// }

struct TestMctp<'a> {
    _mock_mctp: &'a MockMctp<'a>,
}

impl<'a> TestMctp<'a> {
    pub fn new(_mock_mctp: &'static MockMctp<'a>) -> Self {
        Self { _mock_mctp }
    }
}

impl<'a> TestClient for TestMctp<'a> {
    fn test_result(&self, passed: bool) {
        if passed {
            println!("MCTP test passed");
            crate::io::exit_emulator(0);
        } else {
            println!("MCTP test failed");
            crate::io::exit_emulator(1);
        }
    }
}
