// Licensed under the Apache-2.0 license

// Re-export shared firmware API
pub use caliptra_core_firmware::*;

#[cfg(feature = "2_0")]
pub use caliptra_auth_man_gen_2_0 as caliptra_auth_man_gen;
#[cfg(feature = "2_1")]
pub use caliptra_auth_man_gen_2_1 as caliptra_auth_man_gen;

#[cfg(feature = "2_0")]
pub use caliptra_builder_2_0 as caliptra_builder;
#[cfg(feature = "2_1")]
pub use caliptra_builder_2_1 as caliptra_builder;

#[cfg(feature = "2_0")]
pub use caliptra_emu_bus_2_0 as caliptra_emu_bus;
#[cfg(feature = "2_1")]
pub use caliptra_emu_bus_2_1 as caliptra_emu_bus;

#[cfg(feature = "2_0")]
pub use caliptra_emu_cpu_2_0 as caliptra_emu_cpu;
#[cfg(feature = "2_1")]
pub use caliptra_emu_cpu_2_1 as caliptra_emu_cpu;

#[cfg(feature = "2_0")]
pub use caliptra_emu_derive_2_0 as caliptra_emu_derive;
#[cfg(feature = "2_1")]
pub use caliptra_emu_derive_2_1 as caliptra_emu_derive;

#[cfg(feature = "2_0")]
pub use caliptra_emu_periph_2_0 as caliptra_emu_periph;
#[cfg(feature = "2_1")]
pub use caliptra_emu_periph_2_1 as caliptra_emu_periph;

#[cfg(feature = "2_0")]
pub use caliptra_emu_types_2_0 as caliptra_emu_types;
#[cfg(feature = "2_1")]
pub use caliptra_emu_types_2_1 as caliptra_emu_types;

#[cfg(feature = "2_0")]
pub use caliptra_hw_model_2_0 as caliptra_hw_model;
#[cfg(feature = "2_1")]
pub use caliptra_hw_model_2_1 as caliptra_hw_model;

#[cfg(feature = "2_0")]
pub use caliptra_hw_model_types_2_0 as caliptra_hw_model_types;
#[cfg(feature = "2_1")]
pub use caliptra_hw_model_types_2_1 as caliptra_hw_model_types;

#[cfg(feature = "2_0")]
pub use caliptra_image_crypto_2_0 as caliptra_image_crypto;
#[cfg(feature = "2_1")]
pub use caliptra_image_crypto_2_1 as caliptra_image_crypto;

#[cfg(feature = "2_0")]
pub use caliptra_image_fake_keys_2_0 as caliptra_image_fake_keys;
#[cfg(feature = "2_1")]
pub use caliptra_image_fake_keys_2_1 as caliptra_image_fake_keys;

#[cfg(feature = "2_0")]
pub use caliptra_image_gen_2_0 as caliptra_image_gen;
#[cfg(feature = "2_1")]
pub use caliptra_image_gen_2_1 as caliptra_image_gen;

#[cfg(feature = "2_0")]
pub use caliptra_image_types_2_0 as caliptra_image_types;
#[cfg(feature = "2_1")]
pub use caliptra_image_types_2_1 as caliptra_image_types;

#[cfg(feature = "2_0")]
pub use caliptra_test_2_0 as caliptra_test;
#[cfg(feature = "2_1")]
pub use caliptra_test_2_1 as caliptra_test;

#[cfg(feature = "2_0")]
pub use caliptra_test_harness_2_0 as caliptra_test_harness;
#[cfg(feature = "2_1")]
pub use caliptra_test_harness_2_1 as caliptra_test_harness;

#[cfg(feature = "2_0")]
pub use caliptra_test_harness_types_2_0 as caliptra_test_harness_types;
#[cfg(feature = "2_1")]
pub use caliptra_test_harness_types_2_1 as caliptra_test_harness_types;
