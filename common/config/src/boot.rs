// Licensed under the Apache-2.0 license

/// Trait for accessing and modifying boot configuration.
///
/// This trait abstracts the operations required to manage boot partitions,
/// track their status and boot counts, and control rollback functionality.
#[allow(async_fn_in_trait)]
pub trait BootConfigAsync {
    /// Determines which partition should be booted.
    ///
    /// # Returns
    /// * `PartitionId` - The identifier of the active partition to boot from.
    async fn get_active_partition(&self) -> Result<PartitionId, BootConfigError>;

    /// Retrieves the partition that is currently inactive.
    ///
    /// # Returns
    /// * `PartitionId` - The identifier of the inactive partition.
    async fn get_inactive_partition(&self) -> Result<PartitionId, BootConfigError>;

    /// Retrieves the partition that is pending to be booted.
    /// This partition is the non-active partition that contains staged firmware update image.
    ///
    /// # Returns
    /// * `PartitionId` - The identifier of the pending partition.
    async fn get_pending_partition(&self) -> Result<PartitionId, BootConfigError>;

    /// Sets the active partition to boot from.
    ///
    /// # Arguments
    /// * `partition` - The identifier of the partition to set as active.
    async fn set_active_partition(&mut self, partition: PartitionId)
        -> Result<(), BootConfigError>;

    /// Updates the status of a specified partition.
    ///
    /// # Arguments
    /// * `partition` - The identifier of the partition to update.
    /// * `status` - The new status to assign to the partition.
    async fn set_partition_status(
        &mut self,
        partition: PartitionId,
        status: PartitionStatus,
    ) -> Result<(), BootConfigError>;

    /// Retrieves the current status of a specified partition.
    ///
    /// # Arguments
    /// * `partition` - The identifier of the partition to query.
    ///
    /// # Returns
    /// * `PartitionStatus` - The current status of the partition.
    async fn get_partition_status(
        &self,
        partition: PartitionId,
    ) -> Result<PartitionStatus, BootConfigError>;

    /// Increments the boot count for a specified partition.
    ///
    /// # Arguments
    /// * `partition` - The identifier of the partition whose boot count is to be incremented.
    ///
    /// # Returns
    /// * `Result<u16, BootConfigError>` - The new boot count on success, or an error on failure.
    async fn increment_boot_count(&self, partition: PartitionId) -> Result<u16, BootConfigError>;

    /// Retrieves the boot count for a specified partition.
    ///
    /// # Arguments
    /// * `partition` - The identifier of the partition to query.
    ///
    /// # Returns
    /// * `Result<u16, BootConfigError>` - The current boot count on success, or an error on failure.
    async fn get_boot_count(&self, partition: PartitionId) -> Result<u16, BootConfigError>;

    /// Checks if rollback functionality is enabled.
    ///
    /// # Returns
    /// * `bool` - `true` if rollback is enabled, `false` otherwise.
    async fn is_rollback_enabled(&self) -> Result<bool, BootConfigError>;

    /// Enables or disables rollback functionality.
    ///
    /// # Arguments
    /// * `enable` - The desired rollback enable state.
    async fn set_rollback_enable(&mut self, enable: bool) -> Result<(), BootConfigError>;

    /// Optionally persists the updated configuration.
    ///
    /// This method can be overridden to persist changes to non-volatile storage.
    ///
    /// # Returns
    /// * `Result<(), BootConfigError>` - `Ok(())` if successful, or an error on failure.
    async fn persist(&self) -> Result<(), BootConfigError> {
        Ok(()) // Default: do nothing
    }
}

// Synchronous version of the BootConfigAsync trait
pub trait BootConfig {
    /// Determines which partition should be booted.
    fn get_active_partition(&self) -> Result<PartitionId, BootConfigError>;

    /// Sets the active partition to boot from.
    fn set_active_partition(&mut self, partition: PartitionId) -> Result<(), BootConfigError>;

    /// Updates the status of a specified partition.
    fn set_partition_status(
        &mut self,
        partition: PartitionId,
        status: PartitionStatus,
    ) -> Result<(), BootConfigError>;

    /// Retrieves the current status of a specified partition.
    fn get_partition_status(
        &self,
        partition: PartitionId,
    ) -> Result<PartitionStatus, BootConfigError>;

    /// Increments the boot count for a specified partition.
    fn increment_boot_count(&self, partition: PartitionId) -> Result<u16, BootConfigError>;

    /// Retrieves the boot count for a specified partition.
    fn get_boot_count(&self, partition: PartitionId) -> Result<u16, BootConfigError>;

    /// Checks if rollback functionality is enabled.
    fn is_rollback_enabled(&self) -> Result<bool, BootConfigError>;

    /// Enables or disables rollback functionality.
    fn set_rollback_enable(&mut self, enable: bool) -> Result<(), BootConfigError>;

    /// Optionally persists the updated configuration.
    ///
    /// This method can be overridden to persist changes to non-volatile storage.
    fn persist(&self) -> Result<(), BootConfigError> {
        Ok(()) // Default: do nothing
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionId {
    None = 0x0000_0000,
    A = 0x0000_0001,
    B = 0x0000_0002,
    Staging = 0x0000_0003,
}

impl core::convert::TryFrom<u32> for PartitionId {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000_0000 => Ok(PartitionId::None),
            0x0000_0001 => Ok(PartitionId::A),
            0x0000_0002 => Ok(PartitionId::B),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStatus {
    Invalid = 0x0000,
    Valid = 0x0001,
    BootFailed = 0x0002,
    BootSuccessful = 0x0003,
}

impl core::convert::TryFrom<u16> for PartitionStatus {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(PartitionStatus::Invalid),
            0x0001 => Ok(PartitionStatus::Valid),
            0x0002 => Ok(PartitionStatus::BootFailed),
            0x0003 => Ok(PartitionStatus::BootSuccessful),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackEnable {
    Disabled = 0x0000_0000,
    Enabled = 0x0001_0000,
}

// Define BootConfigError for error handling in BootConfig trait
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootConfigError {
    InvalidPartition,
    InvalidStatus,
    StorageError,
    ReadFailed,
    WriteFailed,
    Unknown,
}
