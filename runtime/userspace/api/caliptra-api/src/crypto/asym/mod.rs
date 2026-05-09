// Licensed under the Apache-2.0 license
pub mod ecdh;
pub mod ecdsa;

pub const ECC_P384_SIGNATURE_SIZE: usize = 96;
pub const ECC_P384_PARAM_X_SIZE: usize = 48;
pub const ECC_P384_PARAM_Y_SIZE: usize = 48;

pub enum KeyExchScheme {
    Ecdh,
}

// Type of Asymmetric Algorithm supported.
// Currently only ECC P384 is supported.
// This can be extended to support PQC algorithms in the future.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AsymAlgo {
    EccP384,
}

impl AsymAlgo {
    pub fn signature_size(&self) -> usize {
        match self {
            AsymAlgo::EccP384 => ECC_P384_SIGNATURE_SIZE,
        }
    }
}
