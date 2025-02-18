use crate::update_sm::UpdateAgentEvents;
use crate::discovery_sm::DiscoveryAgentEvents;

#[derive(Debug, Clone, Default)]
pub enum PldmEvents {
    #[default]
    TestEvent1,
    TestEvent2,
    Discovery(DiscoveryAgentEvents),
    Update(UpdateAgentEvents),
}


