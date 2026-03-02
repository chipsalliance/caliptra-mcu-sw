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
    PARTITION_TABLE, PARTITION_TABLE_COPY_0_OFFSET, PARTITION_TABLE_COPY_1_OFFSET,
    prepare_dual_write, select_partition_table,
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

    async fn read_partition_table_copy(&self, offset: usize) -> Option<PartitionTable> {
        let mut buf: [u8; core::mem::size_of::<PartitionTable>()] =
            [0; core::mem::size_of::<PartitionTable>()];
        if self
            .flash_partition_syscall
            .read(offset, core::mem::size_of::<PartitionTable>(), &mut buf)
            .await
            .is_err()
        {
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

    pub async fn read_partition_table(&self) -> Result<PartitionTable, ErrorCode> {
        let copy_0 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET)
            .await;
        let copy_1 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET)
            .await;

        match select_partition_table(copy_0, copy_1) {
            Some(pt) => Ok(pt),
            None => Err(ErrorCode::Fail),
        }
    }

    async fn write_partition_table_dual(
        &self,
        pt: &mut PartitionTable,
    ) -> Result<(), ErrorCode> {
        let gen_0 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET)
            .await
            .map(|p| p.generation);
        let gen_1 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET)
            .await
            .map(|p| p.generation);

        let (first, second) = prepare_dual_write(
            pt,
            gen_0,
            gen_1,
            PARTITION_TABLE_COPY_0_OFFSET as u32,
            PARTITION_TABLE_COPY_1_OFFSET as u32,
        );

        self.flash_partition_syscall
            .write(
                first as usize,
                core::mem::size_of::<PartitionTable>(),
                pt.as_bytes(),
            )
            .await?;
        self.flash_partition_syscall
            .write(
                second as usize,
                core::mem::size_of::<PartitionTable>(),
                pt.as_bytes(),
            )
            .await?;

        Ok(())
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
        self.write_partition_table_dual(&mut partition_table)
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
        let active_partition = partition_table.get_active_partition_id();
        Ok(active_partition)
    }

    async fn get_pending_partition(&self) -> Result<PartitionId, BootConfigError> {
        let partition_table = self
            .read_partition_table()
            .await
            .map_err(|_| BootConfigError::ReadFailed)?;
        let active_partition = partition_table.get_active_partition_id();

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
        let active_partition = partition_table.get_active_partition_id();
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
        self.write_partition_table_dual(&mut partition_table)
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

        // Dual-copy write
        let gen_0 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_0_OFFSET)
            .await
            .map(|p| p.generation);
        let gen_1 = self
            .read_partition_table_copy(PARTITION_TABLE_COPY_1_OFFSET)
            .await
            .map(|p| p.generation);

        let (first, second) = prepare_dual_write(
            &mut partition_table,
            gen_0,
            gen_1,
            PARTITION_TABLE_COPY_0_OFFSET as u32,
            PARTITION_TABLE_COPY_1_OFFSET as u32,
        );

        self.flash_partition_syscall
            .write(
                first as usize,
                core::mem::size_of::<PartitionTable>(),
                partition_table.as_bytes(),
            )
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        self.flash_partition_syscall
            .write(
                second as usize,
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
        self.write_partition_table_dual(&mut partition_table)
            .await
            .map_err(|_| BootConfigError::WriteFailed)?;
        Ok(())
    }
}
