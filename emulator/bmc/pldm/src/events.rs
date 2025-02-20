use crate::discovery_sm::DiscoveryAgentEvents;
use crate::update_sm::UpdateAgentEvents;

#[derive(Debug, Clone, Default)]
pub enum PldmEvents {
    #[default]
    TestEvent1,
    TestEvent2,
    Discovery(DiscoveryAgentEvents),
    Update(UpdateAgentEvents),
}
