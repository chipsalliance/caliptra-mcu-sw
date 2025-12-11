// Licensed under the Apache-2.0 license

use libsyscall_caliptra::flash::SpiFlash;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_platform::ErrorCode;
use mcu_config::boot::{
    BootConfigAsync, BootConfigError, PartitionId, PartitionStatus, RollbackEnable,
};
use mcu_config::flash::FlashPartition;
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
use zerocopy::{FromBytes, IntoBytes};

pub struct FlashBootConfig {
    flash_partition_syscall: SpiFlash<DefaultSyscalls>,
}

impl Default for FlashBootConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashBootConfig {
    pub fn new() -> Self {
        FlashBootConfig {
            flash_partition_syscall: SpiFlash::<DefaultSyscalls>::new(PARTITION_TABLE.driver_num),
        }
    }

    pub async fn read_partition_table(&self) -> Result<PartitionTable, ErrorCode> {
        let mut partition_table_data: [u8; core::mem::size_of::<PartitionTable>()] =
            [0; core::mem::size_of::<PartitionTable>()];
        self.flash_partition_syscall
            .read(
                0,
                core::mem::size_of::<PartitionTable>(),
                &mut partition_table_data,
            )
            .await?;
        let (partition_table, _) =
            PartitionTable::read_from_prefix(&partition_table_data).map_err(|_| ErrorCode::Fail)?;
        // Verify checksum
        let checksum_calculator = StandAloneChecksumCalculator::new();
        if !partition_table.verify_checksum(&checksum_calculator) {
            return Err(ErrorCode::Fail);
        }
        Ok(partition_table)
    }

    pub fn get_partition_from_id(
        &self,
        partition_id: PartitionId,
    ) -> Result<FlashPartition, ErrorCode> {
        match partition_id {
            PartitionId::A => Ok(IMAGE_A_PARTITION),
            PartitionId::B => Ok(IMAGE_B_PARTITION),
            _ => Err(ErrorCode::Fail),
        }
    }
}

impl BootConfigAsync for FlashBootConfig {
    async fn get_partition_status(
        &self,
        partition_id: PartitionId,
    ) -> Result<PartitionStatus, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => Ok(partition_table
                .partition_a_status
                .try_into()
                .unwrap_or(PartitionStatus::Invalid)),
            PartitionId::B => Ok(partition_table
                .partition_b_status
                .try_into()
                .unwrap_or(PartitionStatus::Invalid)),
            _ => Err(BootConfigError::InvalidPartition),
        }
    }

    async fn set_partition_status(
        &mut self,
        partition_id: PartitionId,
        status: PartitionStatus,
    ) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => partition_table.partition_a_status = status as u16,
            PartitionId::B => partition_table.partition_b_status = status as u16,
            _ => return Err(BootConfigError::InvalidPartition),
        }
        // Write the updated partition table back to flash
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        self.flash_partition_syscall
            .write(
                0,
                core::mem::size_of::<PartitionTable>(),
                partition_table.as_bytes(),
            )
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    async fn is_rollback_enabled(&self) -> Result<bool, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        Ok(partition_table.rollback_enable == RollbackEnable::Enabled as u32)
    }

    async fn get_active_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        let (active_partition, _) = partition_table.get_active_partition();
        Ok(active_partition)
    }

    async fn get_pending_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        let (active_partition, _) = partition_table.get_active_partition();

        let other_partition = match active_partition {
            PartitionId::A => Ok(PartitionId::B),
            PartitionId::B => Ok(PartitionId::A),
            _ => Ok(PartitionId::A),
        }?;

        if self.get_partition_status(other_partition).await? == PartitionStatus::Valid {
            Ok(other_partition)
        } else {
            Err(BootConfigError::InvalidStatus)
        }
    }

    async fn get_inactive_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        let (active_partition, _) = partition_table.get_active_partition();
        match active_partition {
            PartitionId::A => Ok(PartitionId::B),
            PartitionId::B => Ok(PartitionId::A),
            _ => Ok(PartitionId::A),
        }
    }

    async fn set_active_partition(
        &mut self,
        partition_id: PartitionId,
    ) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.set_active_partition(partition_id);
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_partition_syscall
            .write(
                0,
                core::mem::size_of::<PartitionTable>(),
                partition_table.as_bytes(),
            )
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    async fn increment_boot_count(
        &self,
        partition_id: PartitionId,
    ) -> Result<u16, BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        let boot_count = match partition_id {
            PartitionId::A => {
                partition_table.partition_a_boot_count += 1;
                partition_table.partition_a_boot_count
            }
            PartitionId::B => {
                partition_table.partition_b_boot_count += 1;
                partition_table.partition_b_boot_count
            }
            _ => return Err(BootConfigError::InvalidPartition),
        };
        // Write the updated partition table back to flash
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        self.flash_partition_syscall
            .write(
                0,
                core::mem::size_of::<PartitionTable>(),
                partition_table.as_bytes(),
            )
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(boot_count)
    }

    async fn get_boot_count(&self, partition_id: PartitionId) -> Result<u16, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => Ok(partition_table.partition_a_boot_count),
            PartitionId::B => Ok(partition_table.partition_b_boot_count),
            _ => Err(BootConfigError::InvalidPartition),
        }
    }

    async fn set_rollback_enable(&mut self, enable: bool) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.rollback_enable = if enable {
            RollbackEnable::Enabled as u32
        } else {
            RollbackEnable::Disabled as u32
        };
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_partition_syscall
            .write(
                0,
                core::mem::size_of::<PartitionTable>(),
                partition_table.as_bytes(),
            )
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }
}
