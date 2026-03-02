// Licensed under the Apache-2.0 license

use mcu_config::boot::{BootConfig, BootConfigError, PartitionId, PartitionStatus, RollbackEnable};
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator,
    PARTITION_TABLE_COPY_0_OFFSET, PARTITION_TABLE_COPY_1_OFFSET,
    prepare_dual_write, select_partition_table,
};
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

    fn read_partition_table_copy(&self, offset: usize) -> Option<PartitionTable> {
        let mut buf: [u8; core::mem::size_of::<PartitionTable>()] =
            [0; core::mem::size_of::<PartitionTable>()];
        if self.flash_driver.read(offset, &mut buf).is_err() {
            return None;
        }
        let (pt, _) = PartitionTable::read_from_prefix(&buf).ok()?;
        let calc = StandAloneChecksumCalculator::new();
        if pt.verify_checksum(&calc) {
            Some(pt)
        } else {
            None
        }
    }

    pub fn read_partition_table(&self) -> Result<PartitionTable, ()> {
        let copy_0 = self.read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET);
        let copy_1 = self.read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET);

        match select_partition_table(copy_0, copy_1) {
            Some(pt) => Ok(pt),
            None => {
                romtime::println!(
                    "[mcu-rom] Both partition table copies invalid, creating default"
                );
                let mut pt = PartitionTable::new(
                    PartitionId::A,
                    0,
                    PartitionStatus::Valid,
                    0,
                    PartitionStatus::Invalid,
                    RollbackEnable::Enabled,
                );
                pt.populate_checksum(&StandAloneChecksumCalculator::new());
                Ok(pt)
            }
        }
    }

    fn write_partition_table_dual(&mut self, pt: &mut PartitionTable) -> Result<(), ()> {
        let gen_0 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET)
            .map(|p| p.generation);
        let gen_1 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET)
            .map(|p| p.generation);

        let (first, second) = prepare_dual_write(
            pt,
            gen_0,
            gen_1,
            PARTITION_TABLE_COPY_0_OFFSET as u32,
            PARTITION_TABLE_COPY_1_OFFSET as u32,
        );

        self.flash_driver
            .write(first as usize, pt.as_bytes())
            .map_err(|_| ())?;
        self.flash_driver
            .write(second as usize, pt.as_bytes())
            .map_err(|_| ())?;

        Ok(())
    }
}

impl<'a> BootConfig for FlashBootCfg<'a> {
    fn get_active_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;

        let active_partition = partition_table.get_active_partition_id();
        Ok(active_partition)
    }

    fn set_active_partition(&mut self, partition_id: PartitionId) -> Result<(), BootConfigError> {
        let mut partition_table = self
            .read_partition_table()
            .map_err(|_| BootConfigError::ReadFailed)?;
        partition_table.set_active_partition(partition_id);
        self.write_partition_table_dual(&mut partition_table)
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

        // Dual-copy write
        let gen_0 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET)
            .map(|p| p.generation);
        let gen_1 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET)
            .map(|p| p.generation);

        let (first, second) = prepare_dual_write(
            &mut partition_table,
            gen_0,
            gen_1,
            PARTITION_TABLE_COPY_0_OFFSET as u32,
            PARTITION_TABLE_COPY_1_OFFSET as u32,
        );

        self.flash_driver
            .write(first as usize, partition_table.as_bytes())
            .map_err(|_| BootConfigError::WriteFailed)?;
        self.flash_driver
            .write(second as usize, partition_table.as_bytes())
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
        self.write_partition_table_dual(&mut partition_table)
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
        self.write_partition_table_dual(&mut partition_table)
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
