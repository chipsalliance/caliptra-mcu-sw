// Licensed under the Apache-2.0 license

//! Common variables and methods to coordinate between tests
//! and the platform.

pub mod doe_util;
pub mod i3c;
pub mod i3c_socket;
pub mod i3c_socket_server;
pub mod logging_seed;
pub mod mctp_ctrl_cmds;
pub mod mctp_transport;
pub mod mctp_user_loopback;
pub mod mctp_vdm_transport;
pub mod pldm_request_response;
#[macro_use]
pub mod mctp_util;
pub mod spdm_responder_validator;

pub use caliptra_api_types::DeviceLifecycle;

// Re-export the per-instance emulator state API from its own crate so
// existing consumers of `caliptra_mcu_testing_common::EmulatorState` and
// friends keep working unchanged. The state lives in a separate crate to
// avoid a Cargo dependency cycle with `caliptra-mcu-pldm-ua`.
pub use caliptra_mcu_emulator_state::{
    emulator_ticks_elapsed, get_emulator_state, get_emulator_ticks, init_emulator_state,
    is_emulator_running, set_emulator_running, set_runtime_started, sleep_emulator_ticks,
    spawn_with_emulator_state, stop_emulator, update_ticks, wait_emulator_ticks,
    wait_for_runtime_start, EmulatorState, TICK_NOTIFY_TICKS,
};
