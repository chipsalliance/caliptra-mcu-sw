use crate::update_sm::UpdateAgentEvents as ua_events;
use crate::discovery_sm::DiscoveryAgentEvents as discovery_events;

#[derive(Debug)]
pub enum PldmEvents {
    TestEvent1,
    TestEvent2,
    Discovery(discovery_events),
    Update(ua_events),
}


