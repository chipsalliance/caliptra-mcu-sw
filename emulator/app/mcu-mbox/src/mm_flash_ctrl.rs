use std::fs::{File, OpenOptions};
use std::io::{Read, Result as IoResult, Seek, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use emulator_periph::McuMailbox0External;
use registers_generated::mci::bits::MboxExecute;
use registers_generated::mci::bits::MboxTargetStatus;
use tock_registers::interfaces::{Readable, Writeable};

pub const PAGE_SIZE: usize = 256;
pub const NUM_PAGES: usize = (64 * 1024 * 1024) / PAGE_SIZE; //64MB flash

/// Enum for mailbox flash operations.
#[derive(Debug, Copy, Clone, PartialEq)]
enum FlashOp {
    Read,
    Write,
    Erase,
    Unknown,
}

impl From<u32> for FlashOp {
    fn from(cmd: u32) -> Self {
        match cmd {
            1 => FlashOp::Read,
            2 => FlashOp::Write,
            3 => FlashOp::Erase,
            _ => FlashOp::Unknown,
        }
    }
}

fn initialize_flash_file(
    file: &mut File,
    size: usize,
    initial_content: Option<&[u8]>,
) -> IoResult<()> {
    let mut remaining = size;
    if let Some(content) = initial_content {
        let write_size = std::cmp::min(size, content.len());
        file.write_all(&content[..write_size])?;
        remaining -= write_size;
    }
    let chunk = vec![0xff; 1048576]; // 1MB chunk
    while remaining > 0 {
        let write_size = std::cmp::min(remaining, chunk.len());
        file.write_all(&chunk[..write_size])?;
        remaining -= write_size;
    }
    Ok(())
}

pub struct ImaginaryFlashController {
    mbox: McuMailbox0External,
    flash_file: Arc<Mutex<File>>,
}

impl ImaginaryFlashController {
    pub fn new(
        mbox: McuMailbox0External,
        file_name: Option<PathBuf>,
        initial_content: Option<&[u8]>,
    ) -> Self {
        let path = file_name.unwrap_or_else(|| PathBuf::from("emulator_mm_flash.bin"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("Failed to open flash file");

        let capacity = NUM_PAGES * PAGE_SIZE;
        let metadata = file.metadata().expect("Failed to get file metadata");
        if metadata.len() < capacity as u64 || initial_content.is_some() {
            file.set_len(capacity as u64)
                .expect("Failed to set file length");
            file.seek(std::io::SeekFrom::Start(0)).unwrap();
            initialize_flash_file(&mut file, capacity, initial_content)
                .expect("Failed to init flash");
        }

        Self {
            mbox,
            flash_file: Arc::new(Mutex::new(file)),
        }
    }

    pub fn poll_mailbox_and_process(&self) {
        let execute = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_execute()
            .reg
            .get();

        if execute != MboxExecute::Execute::SET.value {
            return;
        }

        // Check target user and target use valid bit before processing
        let target_user = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user();

        let target_user_valid = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user_valid()
            .reg
            .get();

        if target_user != u32::from(self.mbox.soc_agent) || (target_user_valid == 0) {
            println!(
                "[xs debug]poll_mailbox_and_process: target_user invalid: target_user={} target_user_valid={}",
                target_user, target_user_valid
            );
            return;
        }

        let cmd = self.mbox.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_cmd();
        // Read page number and size from SRAM offsets 0 and 1
        let page_num = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_sram(0);
        let page_size_reg = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_sram(1);

        let op = FlashOp::from(cmd);

        println!(
            "[xs debug]poll_mailbox_and_process: cmd={} op={:?} page_num={} page_size={}",
            cmd, op, page_num, page_size_reg
        );

        let done_bit = MboxTargetStatus::Done::SET.value;

        let status_field = match op {
            FlashOp::Read => {
                if page_num < NUM_PAGES as u32 && page_size_reg as usize == PAGE_SIZE {
                    let mut page_buf = vec![0u8; PAGE_SIZE];
                    let io_res = {
                        let mut file = self.flash_file.lock().unwrap();
                        file.seek(std::io::SeekFrom::Start(page_num as u64 * PAGE_SIZE as u64))
                            .and_then(|_| file.read_exact(&mut page_buf))
                    };
                    if io_res.is_ok() {
                        for (i, chunk) in page_buf.chunks(4).enumerate() {
                            let word = chunk
                                .iter()
                                .enumerate()
                                .fold(0u32, |acc, (j, &b)| acc | ((b as u32) << (j * 8)));
                            self.mbox
                                .regs
                                .lock()
                                .unwrap()
                                .write_mcu_mbox0_csr_mbox_sram(word, i);
                        }
                        self.mbox
                            .regs
                            .lock()
                            .unwrap()
                            .write_mcu_mbox0_csr_mbox_dlen(PAGE_SIZE as u32);
                        MboxTargetStatus::Status::CmdComplete.value
                    } else {
                        MboxTargetStatus::Status::CmdFailure.value
                    }
                } else {
                    MboxTargetStatus::Status::CmdFailure.value
                }
            }
            FlashOp::Write => {
                if page_num < NUM_PAGES as u32 && page_size_reg as usize == PAGE_SIZE {
                    let mut page_buf = vec![0u8; PAGE_SIZE];
                    for i in 0..(PAGE_SIZE / 4) {
                        let word = self
                            .mbox
                            .regs
                            .lock()
                            .unwrap()
                            .read_mcu_mbox0_csr_mbox_sram(2 + i);
                        for j in 0..4 {
                            page_buf[i * 4 + j] = ((word >> (j * 8)) & 0xff) as u8;
                        }
                    }
                    let io_res = {
                        let mut file = self.flash_file.lock().unwrap();
                        file.seek(std::io::SeekFrom::Start(page_num as u64 * PAGE_SIZE as u64))
                            .and_then(|_| file.write_all(&page_buf))
                    };
                    if io_res.is_ok() {
                        MboxTargetStatus::Status::CmdComplete.value
                    } else {
                        MboxTargetStatus::Status::CmdFailure.value
                    }
                } else {
                    MboxTargetStatus::Status::CmdFailure.value
                }
            }
            FlashOp::Erase => {
                if page_num < NUM_PAGES as u32 && page_size_reg as usize == PAGE_SIZE {
                    let erase_buf = vec![0xFFu8; PAGE_SIZE];
                    let io_res = {
                        let mut file = self.flash_file.lock().unwrap();
                        file.seek(std::io::SeekFrom::Start(page_num as u64 * PAGE_SIZE as u64))
                            .and_then(|_| file.write_all(&erase_buf))
                    };
                    if io_res.is_ok() {
                        MboxTargetStatus::Status::CmdComplete.value
                    } else {
                        MboxTargetStatus::Status::CmdFailure.value
                    }
                } else {
                    MboxTargetStatus::Status::CmdFailure.value
                }
            }
            FlashOp::Unknown => MboxTargetStatus::Status::CmdFailure.value,
        };

        // Update the target status register
        self.mbox
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_status(caliptra_emu_bus::ReadWriteRegister::new(
                (status_field & 0xf) | done_bit,
            ));

        // Wait for EXECUTE bit to transition from SET to CLEAR,
        // then for a new SET (next request)
        // This avoids missing back-to-back requests.
        let mut prev_execute = MboxExecute::Execute::SET.value;
        // Wait for transition SET -> CLEAR
        loop {
            let curr_execute = self
                .mbox
                .regs
                .lock()
                .unwrap()
                .read_mcu_mbox0_csr_mbox_execute()
                .reg
                .get();
            if prev_execute == MboxExecute::Execute::SET.value
                && curr_execute == MboxExecute::Execute::CLEAR.value
            {
                // Transition detected: SET -> CLEAR
                break;
            }
            prev_execute = curr_execute;
            std::thread::sleep(std::time::Duration::from_micros(10));
        }
    }
}
