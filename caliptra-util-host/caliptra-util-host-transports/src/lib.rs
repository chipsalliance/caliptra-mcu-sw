//! Additional transport implementations

pub mod tcp_transport;
pub mod mock_transport;

#[cfg(feature = "libpldm-bridge")]
pub mod libpldm_bridge;

#[cfg(feature = "libspdm-bridge")]
pub mod libspdm_bridge;

pub use tcp_transport::TcpTransport;
pub use mock_transport::MockTransport;

// Re-export core transport types
pub use caliptra_util_host_core::transport::*;