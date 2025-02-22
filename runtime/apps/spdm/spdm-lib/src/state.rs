// Licensed under the Apache-2.0 license

use crate::protocol::SpdmVersion;

pub struct State {
    connection_state: ConnectionState,
    version_number: SpdmVersion,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            connection_state: ConnectionState::NotStarted,
            version_number: SpdmVersion::default(),
        }
    }

    pub fn reset(&mut self) {
        self.connection_state = ConnectionState::NotStarted;
        self.version_number = SpdmVersion::default();
    }

    pub fn connection_state(&self) -> ConnectionState {
        self.connection_state
    }

    pub fn set_connection_state(&mut self, connection_state: ConnectionState) {
        self.connection_state = connection_state;
    }

    pub fn version_number(&self) -> SpdmVersion {
        self.version_number
    }

    pub fn set_version_number(&mut self, version_number: SpdmVersion) {
        self.version_number = version_number;
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ConnectionState {
    NotStarted,
    AfterVersion,
    AfterCapabilities,
    AfterNegotiateAlgorithms,
}
