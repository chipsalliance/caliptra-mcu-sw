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
    /// DEVICE_RESET: reserved value in Reset Control field (byte 0).
    DeviceResetInvalidResetControl = 5,
    /// DEVICE_RESET: reserved value in Forced Recovery field (byte 1).
    DeviceResetInvalidForcedRecoveryMode = 6,
    /// DEVICE_RESET: reserved value in Interface Control field (byte 2).
    DeviceResetInvalidInterfaceControl = 7,
    /// Message slice is too short for the expected command.
    MessageTooShort = 8,
    /// Message slice is longer than the expected command.
    MessageTooLong = 9,
    /// RECOVERY_CTRL: reserved value in Image Selection field (byte 1).
    RecoveryCtrlInvalidImageSelection = 10,
    /// RECOVERY_CTRL: reserved value in Activate field (byte 2).
    RecoveryCtrlInvalidActivate = 11,
    /// RECOVERY_STATUS: reserved value in Device Recovery Status field (byte 0, bits 0-3).
    RecoveryStatusInvalidStatus = 12,
    /// RECOVERY_STATUS: image_index exceeds 4-bit range (0-15).
    RecoveryStatusImageIndexOutOfRange = 13,
}
