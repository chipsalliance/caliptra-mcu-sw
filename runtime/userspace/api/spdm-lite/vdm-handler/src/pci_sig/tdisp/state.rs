// Licensed under the Apache-2.0 license

//! Fixed-size TDISP responder state.

use core::cell::Cell;

use super::protocol::{InterfaceId, START_INTERFACE_NONCE_SIZE};

/// Maximum number of TDISP interfaces tracked by the responder.
pub const MAX_TDISP_INTERFACES: usize = 64;

pub(crate) struct TdispState {
    interfaces: [Cell<Option<TdispInterfaceState>>; MAX_TDISP_INTERFACES],
}

impl TdispState {
    pub(crate) const fn new() -> Self {
        Self {
            interfaces: [const { Cell::new(None) }; MAX_TDISP_INTERFACES],
        }
    }

    pub(crate) fn interface_state(&self, interface_id: InterfaceId) -> Option<TdispInterfaceState> {
        self.interfaces.iter().find_map(|slot| match slot.get() {
            Some(state) if state.interface_id == interface_id => Some(state),
            _ => None,
        })
    }

    pub(crate) fn init_interface(&self, interface_id: InterfaceId) -> bool {
        if let Some(slot) = self
            .interfaces
            .iter()
            .find(|slot| matches!(slot.get(), Some(state) if state.interface_id == interface_id))
        {
            slot.set(Some(TdispInterfaceState::new(interface_id)));
            return true;
        }
        if let Some(slot) = self.interfaces.iter().find(|slot| slot.get().is_none()) {
            slot.set(Some(TdispInterfaceState::new(interface_id)));
            return true;
        }
        false
    }

    pub(crate) fn set_nonce(
        &self,
        interface_id: InterfaceId,
        nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
    ) -> bool {
        if let Some(slot) = self
            .interfaces
            .iter()
            .find(|slot| matches!(slot.get(), Some(state) if state.interface_id == interface_id))
        {
            slot.set(Some(TdispInterfaceState {
                interface_id,
                start_interface_nonce: nonce,
            }));
            return true;
        }
        false
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TdispInterfaceState {
    interface_id: InterfaceId,
    pub(crate) start_interface_nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
}

impl TdispInterfaceState {
    const fn new(interface_id: InterfaceId) -> Self {
        Self {
            interface_id,
            start_interface_nonce: None,
        }
    }
}
