// Licensed under the Apache-2.0 license

pub enum TdispError {
    Success = 0x00,
    InvalidRequest = 0x01,
    Busy = 0x03,
    InvalidInterfaceState = 0x04,
    Unspecified = 0x05,
    UnsupportedRequest = 0x07,
    VersionMismatch = 0x41,
    VendorSpecificError = 0xFF,
    InvalidInterface = 0x101,
    InvalidNonce = 0x102,
    InsuficientEntropy = 0x103,
    InvalidDeviceConfiguration = 0x104,
}