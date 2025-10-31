//! Plugin system for transport layer
//! 
//! Supports dynamic loading of transport implementations and factories

pub mod loader;
pub mod interface;

#[cfg(feature = "c_plugins")]
pub mod c_bindings;

pub use loader::*;
pub use interface::*;

#[cfg(feature = "c_plugins")]
pub use c_bindings::*;