// Licensed under the Apache-2.0 license

/// A representation of the various errors which can arise in handling the OCP Recovery protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OcpError {
    /// PROT_CAP: identification (bit 0) MUST be set.
    ProtCapIdentificationRequired = 0,
    /// PROT_CAP: device_status (bit 4) MUST be set.
    ProtCapDeviceStatusRequired = 1,
    /// PROT_CAP: at least one of local_c_image_support (bit 6) or push_c_image_support (bit 7) MUST be set.
    ProtCapCImageSupportRequired = 2,
    /// PROT_CAP: recovery_memory_access (bit 5) MUST be set when push_c_image_support (bit 7) is set.
    ProtCapRecoveryMemoryAccessRequired = 3,
    /// The provided buffer is too small to hold the serialized message.
    BufferTooSmall = 4,
}
