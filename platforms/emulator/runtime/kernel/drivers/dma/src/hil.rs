// Licensed under the Apache-2.0 license.

//! Re-export DMA HIL types with legacy names expected by ExternalOTP driver.
//!
//! The canonical definitions live in `caliptra_mcu_capsules_runtime::dma::hil`;
//! this module provides aliases for backward compatibility.

pub use caliptra_mcu_capsules_runtime::dma::hil::Dma as DMA;
pub use caliptra_mcu_capsules_runtime::dma::hil::DmaClient as DMAClient;
pub use caliptra_mcu_capsules_runtime::dma::hil::DmaError as DMAError;
pub use caliptra_mcu_capsules_runtime::dma::hil::DmaRoute;
pub use caliptra_mcu_capsules_runtime::dma::hil::DmaStatus as DMAStatus;
