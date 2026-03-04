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
    /// DEVICE_RESET: Byte pattern in the Device Reset is invalid.
    DeviceResetInvalid = 5,
    /// Message slice is too short for the expected command.
    MessageTooShort = 6,
    /// Message slice is longer than the expected command.
    MessageTooLong = 7,
    /// RECOVERY_CTRL: Byte pattern in the recovery control is invalid.
    RecoveryCtrlInvalid = 8,
    /// RECOVERY_STATUS: image_index exceeds 4-bit range (0-15).
    RecoveryStatusImageIndexOutOfRange = 9,
    /// RECOVERY_STATUS: reserved value in Device Recovery Status field (byte 0, bits 0-3).
    RecoveryStatusInvalidStatus = 10,
    /// INDIRECT_CTRL: IMO is not 4-byte aligned (bits 1:0 must be zero).
    IndirectCtrlImoNotAligned = 11,
    /// INDIRECT_STATUS: reserved CMS region type value (byte 1, bits 0-2).
    IndirectStatusInvalidCmsRegionType = 12,
    /// INDIRECT_FIFO_CTRL: reserved value in Reset field (byte 1).
    IndirectFifoCtrlInvalid = 13,
    /// DEVICE_STATUS: vendor status exceeds maximum length of 248 bytes.
    DeviceStatusVendorStatusTooLong = 14,
    /// DEVICE_STATUS: heartbeat value exceeds 12-bit range (0-4095).
    DeviceStatusHeartbeatOutOfRange = 15,
    /// DEVICE_STATUS: VendorSpecific recovery reason code is not in range 0x80-0xFF.
    DeviceStatusInvalidVendorReasonCode = 16,
    /// HW_STATUS: reserved or out-of-range composite temperature value.
    HwStatusInvalidCompositeTemp = 17,
    /// HW_STATUS: vendor-specific HW status exceeds maximum length of 251 bytes.
    HwStatusVendorStatusTooLong = 18,
    /// DEVICE_ID: vendor-specific string exceeds maximum length of 231 bytes.
    DeviceIdVendorStringTooLong = 19,
    /// A CMS region buffer is empty or its length is not a multiple of 4.
    InvalidCmsBufferSize = 20,
}

/// Errors returned by CMS region operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsError {
    /// Attempted to write to a read-only region.
    ReadOnly,
    /// Attempted to read from a write-only region.
    WriteOnly,
    /// Attempted to push into a full FIFO.
    FifoFull,
    /// Attempted to pop from an empty FIFO.
    FifoEmpty,
    /// Attempted a transaction on a polling region that is not ready.
    PollingNotReady,
}
