// Licensed under the Apache-2.0 license

use mcu_config::boot::{BootConfig, BootConfigError, PartitionId, PartitionStatus, RollbackEnable};
use mcu_config_emulator::flash::{PartitionTable, StandAloneChecksumCalculator};
use mcu_rom_common::flash::flash_partition::FlashPartition;
use zerocopy::{FromBytes, IntoBytes};
pub struct FlashBootCfg<'a> {
    flash_driver: &'a mut FlashPartition<'a>,
}

impl<'a> FlashBootCfg<'a> {
    #[allow(dead_code)]
    pub fn new(flash_driver: &'a mut FlashPartition<'a>) -> Self {
        Self { flash_driver }
    }

    pub fn read_partition_table(&self) -> Result<PartitionTable, ()> {
        let mut partition_table_data: [u8; core::mem::size_of::<PartitionTable>()] =
            [0; core::mem::size_of::<PartitionTable>()];
        self.flash_driver
            .read(0, &mut partition_table_data)
            .map_err(|_| ())?;

        let (partition_table, _) =
            PartitionTable::read_from_prefix(&partition_table_data).map_err(|_| ())?;
        // Verify checksum
        let checksum_calculator = StandAloneChecksumCalculator::new();
        if !partition_table.verify_checksum(&checksum_calculator) {
            return Err(());
        }
        Ok(partition_table)
    }
}

impl<'a> BootConfig for FlashBootCfg<'a> {
    fn get_active_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;

        let (active_partition, _) = partition_table.get_active_partition();
        Ok(active_partition)
    }

    fn set_active_partition(&mut self, partition_id: PartitionId) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.set_active_partition(partition_id);
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn increment_boot_count(&self, partition_id: PartitionId) -> Result<u16, BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
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

        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(boot_count)
    }

    fn get_boot_count(&self, partition_id: PartitionId) -> Result<u16, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => Ok(partition_table.partition_a_boot_count),
            PartitionId::B => Ok(partition_table.partition_b_boot_count),
            _ => Err(BootConfigError::InvalidPartition),
        }
    }

    fn set_rollback_enable(&mut self, enable: bool) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.rollback_enable = if enable {
            RollbackEnable::Enabled as u32
        } else {
            RollbackEnable::Disabled as u32
        };
        partition_table.populate_checksum(&StandAloneChecksumCalculator::new());
        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn set_partition_status(
        &mut self,
        partition_id: mcu_config::boot::PartitionId,
        status: mcu_config::boot::PartitionStatus,
    ) -> Result<(), mcu_config::boot::BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        match partition_id {
            PartitionId::A => partition_table.partition_a_status = status as u16,
            PartitionId::B => partition_table.partition_b_status = status as u16,
            _ => return Err(BootConfigError::InvalidPartition),
        }
        // Write the updated partition table back to flash
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        self.flash_driver
            .write(0, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }

    fn get_partition_status(
        &self,
        partition_id: mcu_config::boot::PartitionId,
    ) -> Result<mcu_config::boot::PartitionStatus, mcu_config::boot::BootConfigError> {
        let partition_table = self
            .read_partition_table()
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

    fn is_rollback_enabled(&self) -> Result<bool, mcu_config::boot::BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        Ok(partition_table.rollback_enable == RollbackEnable::Enabled as u32)
    }
}
