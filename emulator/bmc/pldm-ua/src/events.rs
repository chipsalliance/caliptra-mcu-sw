// Licensed under the Apache-2.0 license

/// Define the events processed by the PLDM Daemon
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Default)]
pub enum PldmEvents {
    #[default]
    /// Start the PLDM protocol by kick-starting the discovery state machine
    Start,
    /// Stop the PLDM service
    Stop,
    /// Discovery state machine events
    Discovery(crate::discovery_sm::Events),
    /// Firmware Update state machine events
    Update(crate::update_sm::Events),
}
