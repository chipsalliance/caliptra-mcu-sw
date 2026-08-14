// Licensed under the Apache-2.0 license
pub mod ecdh;
pub mod ecdsa;

pub const ECC_P384_SIGNATURE_SIZE: usize = 96;
pub const ECC_P384_PARAM_X_SIZE: usize = 48;
pub const ECC_P384_PARAM_Y_SIZE: usize = 48;
pub const MLDSA87_SIGNATURE_SIZE: usize = 4627;

pub enum KeyExchScheme {
    Ecdh,
}

// Type of Asymmetric Algorithm supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsymAlgo {
    EccP384 = 0x0001,
    MlDsa87 = 0x0002,
}

impl AsymAlgo {
    pub fn signature_size(&self) -> usize {
        match self {
            AsymAlgo::EccP384 => ECC_P384_SIGNATURE_SIZE,
            AsymAlgo::MlDsa87 => MLDSA87_SIGNATURE_SIZE,
        }
    }

    /// Try to convert from a u32 wire value.
    pub fn try_from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(AsymAlgo::EccP384),
            0x0002 => Some(AsymAlgo::MlDsa87),
            _ => None,
        }
    }
}
