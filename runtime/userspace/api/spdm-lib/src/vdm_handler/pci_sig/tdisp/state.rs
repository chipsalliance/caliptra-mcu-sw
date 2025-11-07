// Licensed under the Apache-2.0 license

use crate::vdm_handler::pci_sig::tdisp::protocol::*;

pub(crate) const MAX_TDISP_INTERFACES: usize = 64;

pub(crate) struct TdispState {
    interfaces: [Option<TdispInterfaceState>; MAX_TDISP_INTERFACES],
}

impl TdispState {
    pub(crate) fn new() -> Self {
        TdispState {
            interfaces: [None; MAX_TDISP_INTERFACES],
        }
    }

    #[allow(dead_code)]
    pub(crate) fn interface_state(
        &self,
        interface_id: InterfaceId,
    ) -> Option<&TdispInterfaceState> {
        self.interfaces
            .iter()
            .flatten()
            .find(|intf_state| intf_state.interface_id() == interface_id)
    }

    pub(crate) fn interface_state_mut(
        &mut self,
        interface_id: InterfaceId,
    ) -> Option<&mut TdispInterfaceState> {
        self.interfaces
            .iter_mut()
            .filter_map(|state| state.as_mut())
            .find(|intf_state| intf_state.interface_id() == interface_id)
    }

    pub(crate) fn init_interface(&mut self, interface_id: InterfaceId) -> bool {
        if let Some(state) = self.interface_state_mut(interface_id) {
            state.init(interface_id);
            return true;
        }
        if let Some(slot) = self
            .interfaces
            .iter_mut()
            .find(|state_opt| state_opt.is_none())
        {
            *slot = Some(TdispInterfaceState::new(interface_id));
            return true;
        }
        false // No available slot
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct TdispInterfaceState {
    interface_id: InterfaceId,
    start_interface_nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
}

impl TdispInterfaceState {
    fn new(interface_id: InterfaceId) -> Self {
        TdispInterfaceState {
            interface_id,
            start_interface_nonce: None,
        }
    }

    fn init(&mut self, interface_id: InterfaceId) {
        self.interface_id = interface_id;
        self.start_interface_nonce = None;
    }

    pub(crate) fn interface_id(&self) -> InterfaceId {
        self.interface_id
    }

    pub(crate) fn set_start_interface_nonce(
        &mut self,
        nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
    ) {
        self.start_interface_nonce = nonce;
    }

    #[allow(dead_code)]
    pub(crate) fn start_interface_nonce(&self) -> Option<&[u8; START_INTERFACE_NONCE_SIZE]> {
        self.start_interface_nonce.as_ref()
    }
}
