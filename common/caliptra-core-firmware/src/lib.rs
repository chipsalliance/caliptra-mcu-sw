// Licensed under the Apache-2.0 license
#![no_std]

#[cfg(feature = "2_0")]
pub use caliptra_api_2_0 as caliptra_api;
#[cfg(feature = "2_1")]
pub use caliptra_api_2_1 as caliptra_api;

#[cfg(feature = "2_0")]
pub use caliptra_api_types_2_0 as caliptra_api_types;
#[cfg(feature = "2_1")]
pub use caliptra_api_types_2_1 as caliptra_api_types;

#[cfg(feature = "2_0")]
pub use caliptra_auth_man_types_2_0 as caliptra_auth_man_types;
#[cfg(feature = "2_1")]
pub use caliptra_auth_man_types_2_1 as caliptra_auth_man_types;

#[cfg(feature = "2_0")]
pub use caliptra_drivers_2_0 as caliptra_drivers;
#[cfg(feature = "2_1")]
pub use caliptra_drivers_2_1 as caliptra_drivers;

#[cfg(feature = "2_0")]
pub use caliptra_error_2_0 as caliptra_error;
#[cfg(feature = "2_1")]
pub use caliptra_error_2_1 as caliptra_error;

#[cfg(feature = "2_0")]
pub use caliptra_registers_2_0 as caliptra_registers;
#[cfg(feature = "2_1")]
pub use caliptra_registers_2_1 as caliptra_registers;

#[cfg(feature = "2_0")]
pub use ureg_2_0 as ureg;
#[cfg(feature = "2_1")]
pub use ureg_2_1 as ureg;

#[cfg(feature = "2_0")]
pub use ocp_eat_2_0 as ocp_eat;
#[cfg(feature = "2_1")]
pub use ocp_eat_2_1 as ocp_eat;
