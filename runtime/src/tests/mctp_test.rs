// Licensed under the Apache-2.0 license

use crate::components::mock_mctp::MockMctpComponent;
use crate::timers::InternalTimers;
use capsules_core::virtualizers::virtual_alarm::MuxAlarm;
use capsules_runtime::mctp::mux::MuxMCTPDriver;
use capsules_runtime::mctp::transport_binding::MCTPI3CBinding;
use capsules_runtime::test::mctp::MockMctp;
use capsules_runtime::test::mctp::TestClient;
use core::fmt::Write;
use kernel::component::Component;
use kernel::hil::time::Alarm;
use kernel::static_init;
use romtime::println;

pub fn test_mctp_capsule_loopback<A: Alarm<'static>>(
    mux_mctp: &'static MuxMCTPDriver<'static, MCTPI3CBinding<'static>, A>,
    mux_alarm: &'static MuxAlarm<'static, A>,
) -> Option<u32> {
    // set local EID here if needed.
    let mock_mctp = unsafe {
        MockMctpComponent::new(mux_mctp, mux_alarm)
        .finalize(crate::mock_mctp_component_static!(InternalTimers))
    };
    let mctp_tester = unsafe { static_init!(TestMctp<'static>, TestMctp::new(mock_mctp)) };
    mock_mctp.set_test_client(mctp_tester);
    mock_mctp.run_send_loopback_test();
    None
}

struct TestMctp<'a> {
    _mock_mctp: &'a MockMctp<'a>,
}

impl<'a> TestMctp<'a> {
    pub fn new(_mock_mctp: &'static MockMctp<'a>) -> Self {
        Self { _mock_mctp }
    }
}

impl<'a> TestClient for TestMctp<'a> {
    fn test_result(&self, passed: bool, npassed: usize, ntotal: usize) {
        println!("MCTP test result: {}/{} passed", npassed, ntotal);
        println!(
            "MCTP test result: {}",
            if passed { "PASSED" } else { "FAILED" }
        );
        if passed {
            crate::io::exit_emulator(0);
        } else {
            crate::io::exit_emulator(1);
        }
    }
}
