// Licensed under the Apache-2.0 license

//! Legacy error module — kept for backwards compatibility.
//!
//! New code should use [`crate::errors`] constants directly with
//! [`mcu_error::McuResult`].

pub use crate::errors;
pub use mcu_error::{McuErrorCode, McuResult};
