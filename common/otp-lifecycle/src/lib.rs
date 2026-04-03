// Licensed under the Apache-2.0 license

//! OTP lifecycle state ECC encoding/decoding for the lifecycle controller.
//!
//! Encodes and decodes the SECDED-protected lifecycle state and transition count
//! stored in the OTP LIFE_CYCLE partition.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

/// Errors from OTP lifecycle encoding/decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidState,
    InvalidCount,
    DecodeFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidState => write!(f, "invalid lifecycle state"),
            Error::InvalidCount => write!(f, "invalid lifecycle count"),
            Error::DecodeFailed => write!(f, "unable to decode lifecycle data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

// These are the default lifecycle controller constants from the
// standard Caliptra RTL. These can be overridden by vendors.

// from caliptra-rtl/src/lc_ctrl/rtl/lc_ctrl_state_pkg.sv
const _A0: u16 = 0b0110010010101110; // ECC: 6'b001010
const B0: u16 = 0b0111010111101110; // ECC: 6'b111110
const A1: u16 = 0b0000011110110100; // ECC: 6'b100101
const B1: u16 = 0b0000111111111110; // ECC: 6'b111101
const A2: u16 = 0b0011000111010010; // ECC: 6'b000111
const B2: u16 = 0b0111101111111110; // ECC: 6'b000111
const A3: u16 = 0b0010111001001101; // ECC: 6'b001010
const B3: u16 = 0b0011111101101111; // ECC: 6'b111010
const A4: u16 = 0b0100000111111000; // ECC: 6'b011010
const B4: u16 = 0b0101111111111100; // ECC: 6'b011110
const A5: u16 = 0b1010110010000101; // ECC: 6'b110001
const B5: u16 = 0b1111110110011111; // ECC: 6'b110001
const A6: u16 = 0b1001100110001100; // ECC: 6'b010110
const B6: u16 = 0b1111100110011111; // ECC: 6'b011110
const A7: u16 = 0b0101001100001111; // ECC: 6'b100010
const B7: u16 = 0b1101101101101111; // ECC: 6'b100111
const A8: u16 = 0b0111000101100000; // ECC: 6'b111001
const B8: u16 = 0b0111001101111111; // ECC: 6'b111001
const A9: u16 = 0b0010110001100011; // ECC: 6'b101010
const B9: u16 = 0b0110110001101111; // ECC: 6'b111111
const A10: u16 = 0b0110110100001000; // ECC: 6'b110011
const B10: u16 = 0b0110111110011110; // ECC: 6'b111011
const A11: u16 = 0b1001001001001100; // ECC: 6'b000011
const B11: u16 = 0b1101001111011100; // ECC: 6'b111111
const A12: u16 = 0b0111000001000000; // ECC: 6'b011110
const B12: u16 = 0b0111011101010010; // ECC: 6'b111110
const A13: u16 = 0b1001001010111110; // ECC: 6'b000010
const B13: u16 = 0b1111001011111110; // ECC: 6'b101110
const A14: u16 = 0b1001010011010010; // ECC: 6'b100011
const B14: u16 = 0b1011110111010011; // ECC: 6'b101111
const A15: u16 = 0b0110001010001101; // ECC: 6'b000111
const B15: u16 = 0b0110111111001101; // ECC: 6'b011111
const A16: u16 = 0b1011001000101000; // ECC: 6'b010111
const B16: u16 = 0b1011001011111011; // ECC: 6'b011111
const A17: u16 = 0b0001111001110001; // ECC: 6'b001001
const B17: u16 = 0b1001111111110101; // ECC: 6'b011011
const A18: u16 = 0b0010110110011011; // ECC: 6'b000100
const B18: u16 = 0b0011111111011111; // ECC: 6'b010101
const A19: u16 = 0b0100110110001100; // ECC: 6'b101010
const B19: u16 = 0b1101110110111110; // ECC: 6'b101011

// The C/D values are used for the encoded LC transition counter.

const _C0: u16 = 0b0001010010011110; // ECC: 6'b011100
const D0: u16 = 0b1011011011011111; // ECC: 6'b111100
const C1: u16 = 0b0101101011000100; // ECC: 6'b111000
const D1: u16 = 0b1111101011110100; // ECC: 6'b111101
const C2: u16 = 0b0001111100100100; // ECC: 6'b100011
const D2: u16 = 0b0001111110111111; // ECC: 6'b100111
const C3: u16 = 0b1100111010000101; // ECC: 6'b011000
const D3: u16 = 0b1100111011101111; // ECC: 6'b011011
const C4: u16 = 0b0100001010011111; // ECC: 6'b011000
const D4: u16 = 0b0101101110111111; // ECC: 6'b111100
const C5: u16 = 0b1001111000100010; // ECC: 6'b111000
const D5: u16 = 0b1111111110100010; // ECC: 6'b111110
const C6: u16 = 0b0010011110000110; // ECC: 6'b010000
const D6: u16 = 0b0111011111000110; // ECC: 6'b011101
const C7: u16 = 0b0010111101000110; // ECC: 6'b000110
const D7: u16 = 0b1010111111000110; // ECC: 6'b111111
const C8: u16 = 0b0000001011011011; // ECC: 6'b000001
const D8: u16 = 0b1010101111011011; // ECC: 6'b111011
const C9: u16 = 0b0111000011000110; // ECC: 6'b110001
const D9: u16 = 0b1111111011001110; // ECC: 6'b110011
const C10: u16 = 0b0100001000010010; // ECC: 6'b110110
const D10: u16 = 0b0111001010110110; // ECC: 6'b110111
const C11: u16 = 0b0100101111110001; // ECC: 6'b000001
const D11: u16 = 0b0110101111110011; // ECC: 6'b110111
const C12: u16 = 0b1000100101000001; // ECC: 6'b000001
const D12: u16 = 0b1011110101001111; // ECC: 6'b001011
const C13: u16 = 0b1000000000010001; // ECC: 6'b011111
const D13: u16 = 0b1001100010110011; // ECC: 6'b111111
const C14: u16 = 0b0101110000000100; // ECC: 6'b111110
const D14: u16 = 0b1111111010001101; // ECC: 6'b111110
const C15: u16 = 0b1100001000001001; // ECC: 6'b001011
const D15: u16 = 0b1110011000011011; // ECC: 6'b111011
const C16: u16 = 0b0101001001101100; // ECC: 6'b001000
const D16: u16 = 0b0111111001111110; // ECC: 6'b001001
const C17: u16 = 0b0100001001110100; // ECC: 6'b010100
const D17: u16 = 0b1100101001110111; // ECC: 6'b110110
const C18: u16 = 0b1100000001100111; // ECC: 6'b100000
const D18: u16 = 0b1100011101110111; // ECC: 6'b100101
const C19: u16 = 0b1010000001001010; // ECC: 6'b101111
const D19: u16 = 0b1111011101101010; // ECC: 6'b101111
const C20: u16 = 0b1001001001010101; // ECC: 6'b001110
const D20: u16 = 0b1101111011011101; // ECC: 6'b001111
const C21: u16 = 0b1001010000011011; // ECC: 6'b100000
const D21: u16 = 0b1001111000111011; // ECC: 6'b110101
const C22: u16 = 0b1011101101100001; // ECC: 6'b000100
const D22: u16 = 0b1011111101111111; // ECC: 6'b000110
const C23: u16 = 0b1101101000000111; // ECC: 6'b001100
const D23: u16 = 0b1101111011100111; // ECC: 6'b101110
const ZRO: u16 = 0b0000000000000000; // ECC: 6'b000000

const COUNTS: [[u16; 24]; 25] = [
    [
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, C2, C1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, C2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, D22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        D23, D22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
];

const STATES: [[u16; 20]; 21] = [
    [
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
        ZRO, ZRO,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, A2, A1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, A2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, B18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        B19, B18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
];

pub const LIFECYCLE_STATE_SIZE: usize = 40;
pub const LIFECYCLE_COUNT_SIZE: usize = 48;
pub const LIFECYCLE_MEM_SIZE: usize = LIFECYCLE_STATE_SIZE + LIFECYCLE_COUNT_SIZE;

/// Lifecycle controller state, matching the OpenTitan LC controller encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleControllerState {
    Raw = 0,
    TestUnlocked0 = 1,
    TestLocked0 = 2,
    TestUnlocked1 = 3,
    TestLocked1 = 4,
    TestUnlocked2 = 5,
    TestLocked2 = 6,
    TestUnlocked3 = 7,
    TestLocked3 = 8,
    TestUnlocked4 = 9,
    TestLocked4 = 10,
    TestUnlocked5 = 11,
    TestLocked5 = 12,
    TestUnlocked6 = 13,
    TestLocked6 = 14,
    TestUnlocked7 = 15,
    Dev = 16,
    Prod = 17,
    ProdEnd = 18,
    Rma = 19,
    Scrap = 20,
    PostTransition = 21,
}

impl LifecycleControllerState {
    /// Returns the 30-bit redundant mnemonic for the lifecycle state used by the LC controller.
    pub fn mnemonic(&self) -> u32 {
        let s = (*self as u32) & 0x1F;
        (s << 25) | (s << 20) | (s << 15) | (s << 10) | (s << 5) | s
    }
}

impl core::fmt::Display for LifecycleControllerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::TestUnlocked0 => write!(f, "test_unlocked0"),
            Self::TestLocked0 => write!(f, "test_locked0"),
            Self::TestUnlocked1 => write!(f, "test_unlocked1"),
            Self::TestLocked1 => write!(f, "test_locked1"),
            Self::TestUnlocked2 => write!(f, "test_unlocked2"),
            Self::TestLocked2 => write!(f, "test_locked2"),
            Self::TestUnlocked3 => write!(f, "test_unlocked3"),
            Self::TestLocked3 => write!(f, "test_locked3"),
            Self::TestUnlocked4 => write!(f, "test_unlocked4"),
            Self::TestLocked4 => write!(f, "test_locked4"),
            Self::TestUnlocked5 => write!(f, "test_unlocked5"),
            Self::TestLocked5 => write!(f, "test_locked5"),
            Self::TestUnlocked6 => write!(f, "test_unlocked6"),
            Self::TestLocked6 => write!(f, "test_locked6"),
            Self::TestUnlocked7 => write!(f, "test_unlocked7"),
            Self::Dev => write!(f, "dev"),
            Self::Prod => write!(f, "prod"),
            Self::ProdEnd => write!(f, "prod_end"),
            Self::Rma => write!(f, "rma"),
            Self::Scrap => write!(f, "scrap"),
            Self::PostTransition => write!(f, "post_transition"),
        }
    }
}

impl core::str::FromStr for LifecycleControllerState {
    type Err = &'static str;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "raw" => Ok(Self::Raw),
            "test_unlocked0" => Ok(Self::TestUnlocked0),
            "test_locked0" => Ok(Self::TestLocked0),
            "test_unlocked1" => Ok(Self::TestUnlocked1),
            "test_locked1" => Ok(Self::TestLocked1),
            "test_unlocked2" => Ok(Self::TestUnlocked2),
            "test_locked2" => Ok(Self::TestLocked2),
            "test_unlocked3" => Ok(Self::TestUnlocked3),
            "test_locked3" => Ok(Self::TestLocked3),
            "test_unlocked4" => Ok(Self::TestUnlocked4),
            "test_locked4" => Ok(Self::TestLocked4),
            "test_unlocked5" => Ok(Self::TestUnlocked5),
            "test_locked5" => Ok(Self::TestLocked5),
            "test_unlocked6" => Ok(Self::TestUnlocked6),
            "test_locked6" => Ok(Self::TestLocked6),
            "test_unlocked7" => Ok(Self::TestUnlocked7),
            "dev" | "manuf" | "manufacturing" => Ok(Self::Dev),
            "production" | "prod" => Ok(Self::Prod),
            "prod_end" => Ok(Self::ProdEnd),
            "rma" => Ok(Self::Rma),
            "scrap" => Ok(Self::Scrap),
            "post_transition" => Ok(Self::PostTransition),
            _ => Err("invalid lifecycle state"),
        }
    }
}

impl From<LifecycleControllerState> for u8 {
    fn from(value: LifecycleControllerState) -> Self {
        value as u8
    }
}

impl From<u8> for LifecycleControllerState {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Raw,
            1 => Self::TestUnlocked0,
            2 => Self::TestLocked0,
            3 => Self::TestUnlocked1,
            4 => Self::TestLocked1,
            5 => Self::TestUnlocked2,
            6 => Self::TestLocked2,
            7 => Self::TestUnlocked3,
            8 => Self::TestLocked3,
            9 => Self::TestUnlocked4,
            10 => Self::TestLocked4,
            11 => Self::TestUnlocked5,
            12 => Self::TestLocked5,
            13 => Self::TestUnlocked6,
            14 => Self::TestLocked6,
            15 => Self::TestUnlocked7,
            16 => Self::Dev,
            17 => Self::Prod,
            18 => Self::ProdEnd,
            19 => Self::Rma,
            20 => Self::Scrap,
            21 => Self::PostTransition,
            _ => Self::Raw,
        }
    }
}

impl From<u32> for LifecycleControllerState {
    fn from(value: u32) -> Self {
        ((value & 0x1f) as u8).into()
    }
}

/// Hash a raw LC token using cSHAKE128 with customization string "LC_CTRL".
#[cfg(feature = "sha3")]
pub fn hash_lc_token(raw_token: &[u8; 16]) -> [u8; 16] {
    use sha3::{digest::ExtendableOutput, digest::Update, CShake128, CShake128Core};
    let mut hasher: CShake128 = CShake128::from_core(CShake128Core::new(b"LC_CTRL"));
    hasher.update(raw_token);
    let mut output = [0u8; 16];
    hasher.finalize_xof_into(&mut output);
    output
}

/// Generate the OTP memory contents associated with the lifecycle state.
pub fn lc_generate_state_mem(state: u8) -> Result<[u8; LIFECYCLE_STATE_SIZE]> {
    if state as usize >= STATES.len() {
        return Err(Error::InvalidState);
    }
    let mut result = [0u8; 40];
    let state_data = STATES[state as usize];
    for (i, &value) in state_data.iter().enumerate() {
        result[i * 2] = (value >> 8) as u8;
        result[i * 2 + 1] = (value & 0xFF) as u8;
    }
    Ok(result)
}

/// Generate the OTP memory contents associated with the lifecycle transition count.
pub fn lc_generate_count_mem(count: u8) -> Result<[u8; LIFECYCLE_COUNT_SIZE]> {
    if count >= COUNTS.len() as u8 {
        return Err(Error::InvalidCount);
    }
    let mut result = [0u8; 48];
    let count_data = COUNTS[count as usize];
    for (i, &value) in count_data.iter().enumerate() {
        result[i * 2] = (value >> 8) as u8;
        result[i * 2 + 1] = (value & 0xFF) as u8;
    }
    Ok(result)
}

/// Generate the OTP memory contents associated with the lifecycle state and transition count.
pub fn lc_generate_memory(state: u8, transition_count: u8) -> Result<[u8; LIFECYCLE_MEM_SIZE]> {
    let mut result = [0u8; LIFECYCLE_MEM_SIZE];
    let state_bytes = lc_generate_state_mem(state)?;
    result[..state_bytes.len()].copy_from_slice(&state_bytes);
    let count = lc_generate_count_mem(transition_count)?;
    result[state_bytes.len()..state_bytes.len() + count.len()].copy_from_slice(&count);
    result.reverse();

    Ok(result)
}

/// Decode the lifecycle state from OTP memory (pre-reversal format, i.e., big-endian u16 array).
/// Returns the raw state index (0–20).
pub fn lc_decode_state_mem(mem: &[u8; LIFECYCLE_STATE_SIZE]) -> Result<u8> {
    let mut values = [0u16; 20];
    for (i, value) in values.iter_mut().enumerate() {
        *value = ((mem[i * 2] as u16) << 8) | (mem[i * 2 + 1] as u16);
    }
    for (state_idx, state_row) in STATES.iter().enumerate() {
        if values == *state_row {
            return Ok(state_idx as u8);
        }
    }
    Err(Error::DecodeFailed)
}

/// Decode the lifecycle transition count from OTP memory (pre-reversal format).
pub fn lc_decode_count_mem(mem: &[u8; LIFECYCLE_COUNT_SIZE]) -> Result<u8> {
    let mut values = [0u16; 24];
    for (i, value) in values.iter_mut().enumerate() {
        *value = ((mem[i * 2] as u16) << 8) | (mem[i * 2 + 1] as u16);
    }
    for (count_idx, count_row) in COUNTS.iter().enumerate() {
        if values == *count_row {
            return Ok(count_idx as u8);
        }
    }
    Err(Error::DecodeFailed)
}

/// Decode the lifecycle state and transition count from OTP memory (as stored, i.e., reversed).
/// Returns `(state_index, transition_count)`.
pub fn lc_decode_memory(mem: &[u8; LIFECYCLE_MEM_SIZE]) -> Result<(u8, u8)> {
    let mut reversed = *mem;
    reversed.reverse();
    let state_mem: [u8; LIFECYCLE_STATE_SIZE] = reversed[..LIFECYCLE_STATE_SIZE]
        .try_into()
        .expect("slice length mismatch");
    let count_mem: [u8; LIFECYCLE_COUNT_SIZE] = reversed[LIFECYCLE_STATE_SIZE..]
        .try_into()
        .expect("slice length mismatch");
    let state = lc_decode_state_mem(&state_mem)?;
    let count = lc_decode_count_mem(&count_mem)?;
    Ok((state, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_roundtrip_all_states() {
        for state_val in 0..=20u8 {
            let memory = lc_generate_memory(state_val, 1).unwrap();
            let (decoded_state, decoded_count) = lc_decode_memory(&memory).unwrap();
            assert_eq!(
                decoded_state, state_val,
                "state roundtrip failed for {state_val}"
            );
            assert_eq!(
                decoded_count, 1,
                "count roundtrip failed for state {state_val}"
            );
        }
    }

    #[test]
    fn test_decode_roundtrip_all_counts() {
        let prod_state = 17u8; // Prod
        for count in 0..=24u8 {
            let memory = lc_generate_memory(prod_state, count).unwrap();
            let (decoded_state, decoded_count) = lc_decode_memory(&memory).unwrap();
            assert_eq!(decoded_state, prod_state);
            assert_eq!(
                decoded_count, count,
                "count roundtrip failed for count {count}"
            );
        }
    }

    #[test]
    fn test_decode_raw_state() {
        let memory = lc_generate_memory(0, 0).unwrap(); // Raw = 0
        let (state, count) = lc_decode_memory(&memory).unwrap();
        assert_eq!(state, 0);
        assert_eq!(count, 0);
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn test_hash_lc_token() {
        let raw_token: [u8; 16] = 0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes();
        let expected: [u8; 16] = 0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes();
        assert_eq!(hash_lc_token(&raw_token), expected);
    }
}
