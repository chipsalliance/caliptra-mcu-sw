use crate::discovery_sm::DiscoveryAgentEvents;

#[derive(Debug, Clone, Default)]
pub enum PldmEvents {
    #[default]
    Cancel,
    Discovery(DiscoveryAgentEvents),
}
