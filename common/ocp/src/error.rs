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
    /// INDIRECT_CTRL: IMO is not 4-byte aligned (bits 1:0 must be zero).
    IndirectCtrlImoNotAligned = 14,
    /// INDIRECT_STATUS: reserved CMS region type value (byte 1, bits 0-2).
    IndirectStatusInvalidCmsRegionType = 15,
    /// INDIRECT_FIFO_CTRL: reserved value in Reset field (byte 1).
    IndirectFifoCtrlInvalidReset = 16,
    /// INDIRECT_FIFO_STATUS: reserved CMS region type value (byte 1, bits 0-2).
    IndirectFifoStatusInvalidRegionType = 17,
    /// DEVICE_STATUS: reserved value in Device Status field (byte 0).
    DeviceStatusInvalidStatus = 18,
    /// DEVICE_STATUS: reserved value in Protocol Error field (byte 1).
    DeviceStatusInvalidProtocolError = 19,
    /// DEVICE_STATUS: vendor status exceeds maximum length of 248 bytes.
    DeviceStatusVendorStatusTooLong = 20,
    /// DEVICE_STATUS: heartbeat value exceeds 12-bit range (0-4095).
    DeviceStatusHeartbeatOutOfRange = 21,
    /// DEVICE_STATUS: VendorSpecific recovery reason code is not in range 0x80-0xFF.
    DeviceStatusInvalidVendorReasonCode = 22,
    /// HW_STATUS: reserved or out-of-range composite temperature value.
    HwStatusInvalidCompositeTemp = 23,
    /// HW_STATUS: vendor-specific HW status exceeds maximum length of 251 bytes.
    HwStatusVendorStatusTooLong = 24,
}
