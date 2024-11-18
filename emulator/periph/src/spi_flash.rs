/*++

Licensed under the Apache-2.0 license.

File Name:

    spi_flash.rs

Abstract:

    File contains SPI flash emulation

--*/

use bitfield::Bit;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{cell::RefCell, rc::Rc};

#[derive(PartialEq, Default, Debug, Clone, Copy)]
pub enum IoMode {
    #[default]
    Single,
    Dual,
    Quad,
}

#[derive(PartialEq, Debug)]
pub struct SpiByte {
    pub mode: IoMode,
    pub byte: u8,
}

#[derive(Debug)]
pub enum SpiFlashInput {
    CsLow,
    CsHigh,
    DummyCycles(u32),
    BytesSend(Vec<SpiByte>),
}

#[derive(Debug)]
pub struct SpiFlashOutReq {
    pub mode: IoMode,
    pub n_bytes: u32,
}

#[derive(Debug, PartialEq)]
pub enum SpiFlashErr {
    ImpossibleCodeflow,
    Unimplemented,
    CsChangeUnsupported,
    //    FlashIdle,
    CmdUnsupported,
    InvalidOpcode,
    InvalidAddress,
    InvalidAddressMode,
    InvalidLength,
    SpiFlashBusy, // note: HW dependent mechanism
    WriteDisabled,
    CrossPageProgram,
    PageProgramNotFF,
    EraseAdressUnaligned,
    TooManyDummyCycles,
    ResetBeforeEnable,
    WriteStatusDisabled,
    ModeClockNotFF,
    BytesReqNothingToSend,
    BytesReqZeroBytes,
    BytesReqWrongMode,
    //    BytesReqTooMuch,
    CommandNotSuccessful,
    InvalidTimePassWhileNotIdle,
}

struct FlashPartInfo {
    part_name: &'static str,
    id: &'static [u8],
    chip_size: u32,
    max_page_program_size: u32,
    #[allow(dead_code)] // Unused by implemented flash chip
    max_aai_size: u32,
    se_20_size: u32,
    be_52_size: u32,
    be_d8_size: u32, // Same as 0xdc with 4ba
    ce_60_size: u32,
    ce_c7_size: u32,
    sfdp: &'static [u8],
    // sfdp_read fn pointer TODO
}

#[derive(Default)]
struct FlashState {
    data: Vec<u8>,
    page_buffer: Vec<u8>,
    outbuffer: Vec<SpiByte>,
    idle: bool,
    busy: Option<u64>, // Time that the flash needs to be idle after erase/write
    write_enable: bool,
    four_bytes_address: bool,
    reset_enable: bool,
    quad_enable: bool,
    status_write_enable: bool,
    cmd: JedecSpiFlashCmd,
    bytes_to_receive: u32,
    page_program_get_data: bool,
    mode_clocks_needed: u32,
    dummy_cycles_needed: u32,
    address: u32,
}

#[derive(Debug, Default, IntoPrimitive, TryFromPrimitive, PartialEq)]
#[repr(u8)]
enum JedecSpiFlashCmd {
    #[default]
    Noop = 0x00,
    Wrsr1 = 0x01,
    PageProgram = 0x02,
    Read = 0x03,
    WriteDisable = 0x04,
    Rdsr1 = 0x05,
    WriteEnable = 0x06,
    FastRead = 0x0b,
    FastRead4ba = 0x0c,
    Wrsr3 = 0x11,
    PageProgram4ba = 0x12,
    Read4ba = 0x13,
    Rdsr3 = 0x15,
    SectorErase = 0x20,
    SectorErase4ba = 0x21,
    Wrsr2 = 0x31,
    QuadPageProgram = 0x32,
    QuadPageProgram4ba = 0x34,
    Rdsr2 = 0x35,
    IndividualBlockLock = 0x36,
    IndividualBlockUnlock = 0x39,
    FastReadDualOutput = 0x3b,
    FastReadDualOutput4ba = 0x3c,
    ReadBlockLock = 0x3d,
    ProgramSecurityRegs = 0x42,
    EraseSecurityRegs = 0x44,
    ReadSecurityRegs = 0x48,
    ReadUniqueId = 0x4b,
    Ewsr = 0x50,
    BlockErase52 = 0x52,
    Sfdp = 0x5a,
    ChipErase60 = 0x60,
    ResetEnable = 0x66,
    FastReadQuadOutput = 0x6b,
    FastReadQuadOutput4ba = 0x6c,
    EraseProgramSuspend = 0x75,
    SetBurstWrap = 0x77,
    EraseProgramResume = 0x7a,
    GlobalBlockLock = 0x7e,
    Rems = 0x90,
    RemsDualIO = 0x92,
    RemsQuadIO = 0x94,
    GlobalBlockUnlock = 0x98,
    Reset = 0x99,
    Rdid = 0x9f,
    RelaesePowerDownDeviceId = 0xab,
    Enter4ba = 0xb7,
    PowerDown = 0xb9,
    FastReadDualIO = 0xbb,
    FastReadDualIO4ba = 0xbc,
    FastReadQuadIO = 0xbe,
    SetReadParam = 0xc0,
    ChipErasec7 = 0xc7,
    BlockErased8 = 0xd8,
    BlockErasedc4ba = 0xdc,
    Exit4ba = 0xe9,
    FastReadQuadIO4ba = 0xec,
}

pub struct SpiFlashImpl {
    info: &'static FlashPartInfo,
    state: FlashState,
}

impl<'a> SpiFlashImpl {
    const SUPPORTED_FLASH: &'a [FlashPartInfo] = &[FlashPartInfo {
        part_name: "w25q01jv",
        id: &[0xef, 0x40, 0x21],
        chip_size: 256 * 1024 * 1024,
        max_page_program_size: 256,
        max_aai_size: 0,
        se_20_size: 4 * 1024,
        be_52_size: 32 * 1024,
        be_d8_size: 64 * 1024,
        ce_60_size: 256 * 1024 * 1024,
        ce_c7_size: 256 * 1024 * 1024,
        sfdp: &[
            0x53, 0x46, 0x44, 0x50, 0x06, 0x01, 0x01, 0xff, 0x00, 0x06, 0x01, 0x10, 0x80, 0x00,
            0x00, 0xff, 0x84, 0x00, 0x01, 0x02, 0xd0, 0x00, 0x00, 0xff, 0x03, 0x00, 0x01, 0x02,
            0xf0, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xe5, 0x20, 0xfb, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x44, 0xeb, 0x08, 0x6b,
            0x08, 0x3b, 0x42, 0xbb, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
            0x40, 0xeb, 0x0c, 0x20, 0x0f, 0x52, 0x10, 0xd8, 0x00, 0x00, 0x36, 0x02, 0xa6, 0x00,
            0x82, 0xea, 0x14, 0xe2, 0xe9, 0x63, 0x76, 0x33, 0x7a, 0x75, 0x7a, 0x75, 0xf7, 0xa2,
            0xd5, 0x5c, 0x19, 0xf7, 0x4d, 0xff, 0xe9, 0x70, 0xf9, 0xa5, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a,
            0xf0, 0xff, 0x21, 0xff, 0xdc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ],
    }];

    const SECTOR_ERASE_TIME: u64 = 50;
    const BLOCK_32K_ERASE_TIME: u64 = 120;
    const BLOCK_64K_ERASE_TIME: u64 = 150;
    const CHIP_ERASE_TIME: u64 = 200000;

    pub fn new(name: &str) -> Option<Self> {
        let info = Self::SUPPORTED_FLASH.iter().find(|f| f.part_name == name)?;

        Some(Self {
            info,
            state: FlashState {
                data: vec![0xff; info.chip_size.try_into().unwrap()],
                idle: true,
                busy: None,
                write_enable: false,
                ..Default::default()
            },
        })
    }

    // Process the first byte which is always the command
    fn process_cmd(&mut self, byte: &SpiByte) -> Result<(), SpiFlashErr> {
        if byte.mode != IoMode::Single {
            return Err(SpiFlashErr::CmdUnsupported);
        }

        let cmd: JedecSpiFlashCmd = byte
            .byte
            .try_into()
            .map_err(|_| SpiFlashErr::InvalidOpcode)?;

        let address_length = if self.state.four_bytes_address { 4 } else { 3 };

        // If any command follow Reset enable that is not reset, then reset is disabled
        if self.state.reset_enable && cmd != JedecSpiFlashCmd::Reset {
            self.state.reset_enable = false;
        }

        // Status writes can only follow states write enable
        let is_status_write = matches!(
            cmd,
            JedecSpiFlashCmd::Wrsr1 | JedecSpiFlashCmd::Wrsr2 | JedecSpiFlashCmd::Wrsr3
        );
        if self.state.status_write_enable && !is_status_write {
            self.state.status_write_enable = false;
        }

        if self.state.busy.is_some()
            && !matches!(
                cmd,
                JedecSpiFlashCmd::Rdsr1
                    | JedecSpiFlashCmd::Rdsr2
                    | JedecSpiFlashCmd::Rdsr3
                    | JedecSpiFlashCmd::EraseProgramSuspend
                    | JedecSpiFlashCmd::EraseProgramResume
            )
        {
            return Err(SpiFlashErr::SpiFlashBusy);
        }

        match cmd {
            JedecSpiFlashCmd::Rdid
            | JedecSpiFlashCmd::ChipErase60
            | JedecSpiFlashCmd::ChipErasec7
            | JedecSpiFlashCmd::Enter4ba
            | JedecSpiFlashCmd::Exit4ba
            | JedecSpiFlashCmd::Rdsr1
            | JedecSpiFlashCmd::Rdsr2
            | JedecSpiFlashCmd::Rdsr3
            | JedecSpiFlashCmd::WriteEnable
            // TODO this does not exist on each chip. Some need Write Enable instead
            | JedecSpiFlashCmd::Ewsr
            | JedecSpiFlashCmd::WriteDisable
            | JedecSpiFlashCmd::ResetEnable => {
                self.state.bytes_to_receive = 0;
            }
            JedecSpiFlashCmd::Read => {
                self.state.bytes_to_receive = address_length;
            }
            JedecSpiFlashCmd::Read4ba => {
                self.state.bytes_to_receive = 4;
            }
            JedecSpiFlashCmd::FastRead
            | JedecSpiFlashCmd::FastReadDualOutput
            | JedecSpiFlashCmd::FastReadQuadOutput => {
                self.state.bytes_to_receive = address_length;
                self.state.dummy_cycles_needed = 8;
            }
            JedecSpiFlashCmd::FastRead4ba
            | JedecSpiFlashCmd::FastReadDualOutput4ba
            | JedecSpiFlashCmd::FastReadQuadOutput4ba => {
                self.state.bytes_to_receive = 4;
                self.state.dummy_cycles_needed = 8;
            }
            JedecSpiFlashCmd::FastReadDualIO => {
                self.state.bytes_to_receive = address_length;
                self.state.dummy_cycles_needed = 4;
            }
            JedecSpiFlashCmd::FastReadDualIO4ba => {
                self.state.bytes_to_receive = 4;
                self.state.dummy_cycles_needed = 4;
            }
            // TODO Quad IO mode clocks and dummy cycles have both SPI flash dependent
            // defaults as ways to reconfigure them. When adding new flash this could be moved
            // to struct FlashPartInfo for chip default or implement the configuration mechanism.
            JedecSpiFlashCmd::FastReadQuadIO => {
                self.state.bytes_to_receive = address_length;
                self.state.mode_clocks_needed = 2;
                self.state.dummy_cycles_needed = 6; // TODO configurable
            }
            JedecSpiFlashCmd::FastReadQuadIO4ba => {
                self.state.bytes_to_receive = 4;
                self.state.mode_clocks_needed = 2;
                self.state.dummy_cycles_needed = 6; // TODO configurable
            }
            JedecSpiFlashCmd::PageProgram => {
                if self.state.write_enable {
                    self.state.bytes_to_receive = address_length;
                    self.state.page_program_get_data = false;
                } else {
                    return Err(SpiFlashErr::WriteDisabled);
                }
            }
            JedecSpiFlashCmd::PageProgram4ba => {
                if self.state.write_enable {
                    self.state.bytes_to_receive = 4;
                    self.state.page_program_get_data = false;
                } else {
                    return Err(SpiFlashErr::WriteDisabled);
                }
            }
            JedecSpiFlashCmd::Wrsr1 | JedecSpiFlashCmd::Wrsr2 | JedecSpiFlashCmd::Wrsr3 => {
                if self.state.status_write_enable {
                    // TODO some flash chips write multiple status regs with wrsr1
                    self.state.bytes_to_receive = 1;
                } else {
                    return Err(SpiFlashErr::WriteStatusDisabled)
                }
            }
            JedecSpiFlashCmd::SectorErase
            | JedecSpiFlashCmd::BlockErase52
            | JedecSpiFlashCmd::BlockErased8 => {
                if self.state.write_enable {
                    self.state.bytes_to_receive = address_length;
                } else {
                    return Err(SpiFlashErr::WriteDisabled);
                }
            }
            JedecSpiFlashCmd::SectorErase4ba | JedecSpiFlashCmd::BlockErasedc4ba => {
                if self.state.write_enable {
                    self.state.bytes_to_receive = 4;
                } else {
                    return Err(SpiFlashErr::WriteDisabled);
                }
            }
            JedecSpiFlashCmd::Sfdp => {
                self.state.bytes_to_receive = 3;
                self.state.dummy_cycles_needed = 8;
            }
            JedecSpiFlashCmd::Reset => {
                if !self.state.reset_enable {
                    return Err(SpiFlashErr::ResetBeforeEnable);
                }
                self.state.bytes_to_receive = 0;
            }
            _ => return Err(SpiFlashErr::Unimplemented),
        };
        self.state.cmd = cmd;
        Ok(())
    }

    // Process a byte into address
    // Input:
    //   byte: the SpiByte to process
    //   mode: expected mode off address bytes: Single, Dual, Quad
    //   max_addr: Sanity check for address
    fn process_address(
        &mut self,
        byte: &SpiByte,
        mode: IoMode,
        max_addr: u32,
    ) -> Result<(), SpiFlashErr> {
        if self.state.bytes_to_receive > 4 {
            return Err(SpiFlashErr::InvalidAddress);
        }

        if byte.mode != mode {
            return Err(SpiFlashErr::InvalidAddressMode);
        }
        self.state.address |= (byte.byte as u32) << (8 * (self.state.bytes_to_receive - 1));
        if self.state.address >= max_addr {
            return Err(SpiFlashErr::InvalidAddress);
        }
        self.state.bytes_to_receive -= 1;
        Ok(())
    }

    // Process page programming input. First 3 or 4 bytes are the address.
    // The next bytes are the bytes to program. Up to the flash page size
    // can be send in one go, with the limitation that bytes cannot cross pages.
    fn process_page_program_input(&mut self, byte: &SpiByte) -> Result<(), SpiFlashErr> {
        if byte.mode != IoMode::Single {
            return Err(SpiFlashErr::InvalidAddress);
        }
        if !self.state.page_program_get_data {
            self.process_address(byte, IoMode::Single, self.info.chip_size - 1)?;

            if self.state.bytes_to_receive == 0 {
                self.state.page_program_get_data = true;
                self.state.bytes_to_receive = 1; // Receive an arbitrary number of bytes (never decreased)
            }
        } else {
            let bytes_gathered = self.state.page_buffer.len() as u32;
            let mask = !(self.info.max_page_program_size - 1);
            let page_begin = self.state.address & mask;
            let new_addr = self.state.address + bytes_gathered;

            let clean_up = |state: &mut FlashState| {
                state.page_buffer.clear();
                state.bytes_to_receive = 0;
                state.page_program_get_data = false;
            };
            if page_begin != (new_addr & mask) {
                clean_up(&mut self.state);
                return Err(SpiFlashErr::CrossPageProgram);
            }
            if self.state.data[new_addr as usize] != 0xff {
                clean_up(&mut self.state);
                return Err(SpiFlashErr::PageProgramNotFF);
            }
            self.state.page_buffer.push(byte.byte);
        }
        Ok(())
    }

    // After CS is pulled high page program can begin
    // TODO: The flash is now in a busy state for some time
    // Timing handling will be added later with SPI Host code.
    fn perform_page_program(&mut self) {
        let address = self.state.address as usize;

        for (index, byte) in self.state.page_buffer.iter().enumerate() {
            self.state.data[address + index] = *byte;
        }
        // Page program are TYP from W25Q01JV
        self.state.busy = Some(1);
        self.state.page_buffer.clear();
    }

    // After CS is pulled high erase can begin
    // TODO: The flash is now in a busy state for some time
    // Timing handling will be added later with SPI Host code.
    fn perform_erase(&mut self) -> Result<(), SpiFlashErr> {
        // Should be 0 for full flash erase CMDs
        let address = self.state.address;

        // Erase times are the TYP from W25Q01JV
        let (size, erase_time) = match self.state.cmd {
            JedecSpiFlashCmd::BlockErase52 => {
                (Some(self.info.be_52_size), Self::BLOCK_32K_ERASE_TIME)
            }
            JedecSpiFlashCmd::BlockErased8 | JedecSpiFlashCmd::BlockErasedc4ba => {
                (Some(self.info.be_d8_size), Self::BLOCK_64K_ERASE_TIME)
            }
            JedecSpiFlashCmd::SectorErase | JedecSpiFlashCmd::SectorErase4ba => {
                (Some(self.info.se_20_size), Self::SECTOR_ERASE_TIME)
            }
            JedecSpiFlashCmd::ChipErase60 => (Some(self.info.ce_60_size), Self::CHIP_ERASE_TIME),
            JedecSpiFlashCmd::ChipErasec7 => (Some(self.info.ce_c7_size), Self::CHIP_ERASE_TIME),
            _ => (None, 0),
        };
        let size = size.unwrap();

        if size == 0 {
            return Err(SpiFlashErr::CmdUnsupported);
        }

        let last = address + size - 1;

        if address & !(size - 1) != 0 {
            return Err(SpiFlashErr::EraseAdressUnaligned);
        }
        for idx in address..last {
            self.state.data[idx as usize] = 0xff;
        }

        self.state.busy = Some(erase_time);

        Ok(())
    }

    fn perform_status_write(&mut self) -> Result<(), SpiFlashErr> {
        let input = self.state.address as u8;
        match self.state.cmd {
            // TODO flash specific
            JedecSpiFlashCmd::Wrsr1 => todo!(),
            JedecSpiFlashCmd::Wrsr2 => {
                // TODO implement other bits
                self.state.quad_enable = input.bit(1);
            }
            JedecSpiFlashCmd::Wrsr3 => todo!(),
            _ => {
                return Err(SpiFlashErr::ImpossibleCodeflow);
            }
        }
        // Status program are TYP from W25Q01JV
        self.state.busy = Some(10);

        Ok(())
    }

    fn process_input_bytes(&mut self, bytes: &Vec<SpiByte>) -> Result<(), SpiFlashErr> {
        // Process input
        for byte in bytes {
            if self.state.bytes_to_receive == 0 {
                // If more bytes than needed are received those could be dummy cycles
                // or mode clocks
                let clocks = match byte.mode {
                    IoMode::Single => 8,
                    IoMode::Dual => 4,
                    IoMode::Quad => 2,
                };

                if self.state.mode_clocks_needed != 0 {
                    if self.state.mode_clocks_needed < clocks {
                        return Err(SpiFlashErr::InvalidLength);
                    } else if byte.byte != 0xff {
                        return Err(SpiFlashErr::ModeClockNotFF);
                    } else {
                        self.state.mode_clocks_needed -= clocks;
                        continue;
                    }
                }

                if self.state.dummy_cycles_needed != 0 {
                    if self.state.dummy_cycles_needed < clocks {
                        return Err(SpiFlashErr::InvalidLength);
                    } else {
                        // Sending a random byte also counts as dummy cycle
                        self.state.dummy_cycles_needed -= clocks;
                        continue;
                    }
                }
            }

            match self.state.cmd {
                JedecSpiFlashCmd::Noop => self.process_cmd(byte)?,
                JedecSpiFlashCmd::Read
                | JedecSpiFlashCmd::Read4ba
                | JedecSpiFlashCmd::FastRead
                | JedecSpiFlashCmd::FastRead4ba
                | JedecSpiFlashCmd::FastReadDualOutput
                | JedecSpiFlashCmd::FastReadDualOutput4ba
                | JedecSpiFlashCmd::FastReadQuadOutput
                | JedecSpiFlashCmd::FastReadQuadOutput4ba => {
                    self.process_address(byte, IoMode::Single, self.info.chip_size - 1)?
                }
                JedecSpiFlashCmd::FastReadDualIO | JedecSpiFlashCmd::FastReadDualIO4ba => {
                    self.process_address(byte, IoMode::Dual, self.info.chip_size - 1)?
                }
                JedecSpiFlashCmd::FastReadQuadIO | JedecSpiFlashCmd::FastReadQuadIO4ba => {
                    self.process_address(byte, IoMode::Quad, self.info.chip_size - 1)?;
                }
                JedecSpiFlashCmd::PageProgram | JedecSpiFlashCmd::PageProgram4ba => {
                    self.process_page_program_input(byte)?
                }
                JedecSpiFlashCmd::SectorErase
                | JedecSpiFlashCmd::SectorErase4ba
                | JedecSpiFlashCmd::BlockErase52
                | JedecSpiFlashCmd::BlockErased8
                | JedecSpiFlashCmd::BlockErasedc4ba => {
                    self.process_address(byte, IoMode::Single, self.info.chip_size)?
                }
                JedecSpiFlashCmd::Sfdp => {
                    self.process_address(byte, IoMode::Single, (self.info.sfdp.len() as u32) - 1)?
                }
                // TODO this works differently on some flash chips
                JedecSpiFlashCmd::Wrsr1 | JedecSpiFlashCmd::Wrsr2 | JedecSpiFlashCmd::Wrsr3 => {
                    if byte.mode != IoMode::Single {
                        return Err(SpiFlashErr::InvalidAddressMode);
                    }
                    self.state.address = byte.byte.into();
                    self.state.bytes_to_receive -= 1;
                }
                _ => return Err(SpiFlashErr::Unimplemented),
            }
        }
        Ok(())
    }

    fn process_dummy(&mut self, cycles: u32) -> Result<(), SpiFlashErr> {
        if self.state.dummy_cycles_needed >= cycles {
            self.state.dummy_cycles_needed -= cycles;
            Ok(())
        } else {
            Err(SpiFlashErr::TooManyDummyCycles)
        }
    }

    // After all the CMDs inputs (CMD, ADDR, MODE, DUMMY, ...) have been gathered
    // output bytes
    fn process_output(&mut self) -> Result<Option<Vec<SpiByte>>, SpiFlashErr> {
        match self.state.cmd {
            JedecSpiFlashCmd::Rdid => Ok(Some(
                self.info
                    .id
                    .iter()
                    .map(|b| SpiByte {
                        byte: *b,
                        mode: IoMode::Single,
                    })
                    .collect(),
            )),
            JedecSpiFlashCmd::Read
            | JedecSpiFlashCmd::Read4ba
            | JedecSpiFlashCmd::FastRead
            | JedecSpiFlashCmd::FastRead4ba => Ok(Some(vec![SpiByte {
                mode: IoMode::Single,
                byte: self.state.data[self.state.address as usize],
            }])),
            JedecSpiFlashCmd::FastReadDualOutput
            | JedecSpiFlashCmd::FastReadDualOutput4ba
            | JedecSpiFlashCmd::FastReadDualIO
            | JedecSpiFlashCmd::FastReadDualIO4ba => Ok(Some(vec![SpiByte {
                mode: IoMode::Dual,
                byte: self.state.data[self.state.address as usize],
            }])),
            JedecSpiFlashCmd::FastReadQuadOutput
            | JedecSpiFlashCmd::FastReadQuadOutput4ba
            | JedecSpiFlashCmd::FastReadQuadIO
            | JedecSpiFlashCmd::FastReadQuadIO4ba => Ok(Some(vec![SpiByte {
                mode: IoMode::Quad,
                byte: self.state.data[self.state.address as usize],
            }])),
            JedecSpiFlashCmd::Sfdp => {
                let addr = self.state.address as usize;

                let sfdp_part_slice = &self.info.sfdp[addr..];
                Ok(Some(
                    sfdp_part_slice
                        .iter()
                        .cloned()
                        .map(|b| SpiByte {
                            mode: IoMode::Single,
                            byte: b,
                        })
                        .collect(),
                ))
            }
            JedecSpiFlashCmd::Rdsr1 => {
                let mut status = 0;
                // TODO: use tock registers
                if self.state.busy.is_some() {
                    status |= 1; // BUSY
                }
                if self.state.write_enable {
                    status |= 1 << 1; // Write Enable Latch set
                }
                Ok(Some(vec![SpiByte {
                    mode: IoMode::Single,
                    byte: status,
                }]))
            }
            JedecSpiFlashCmd::Rdsr2 => {
                let mut status = 0;
                // TODO: use tock registers
                if self.state.quad_enable {
                    status |= 1 << 1;
                }
                Ok(Some(vec![SpiByte {
                    mode: IoMode::Single,
                    byte: status,
                }]))
            }
            JedecSpiFlashCmd::Rdsr3 => {
                let mut status = 0;
                // TODO: use tock registers
                if self.state.four_bytes_address {
                    status |= 1 << 0;
                }
                Ok(Some(vec![SpiByte {
                    mode: IoMode::Single,
                    byte: status,
                }]))
            }
            _ => Ok(None),
        }
    }

    /// Process input
    ///
    /// # arguments
    ///
    /// * `input` - SpiFlashInput
    ///
    /// #
    ///
    /// * Err: SpiFlashErr
    /// * Ok(()):
    pub fn input(&mut self, input: &SpiFlashInput) -> Result<(), SpiFlashErr> {
        match input {
            SpiFlashInput::CsLow => {
                if !self.state.idle {
                    // TODO clean up flash state?
                    return Err(SpiFlashErr::CsChangeUnsupported);
                }
                self.state.idle = false;
                self.state.bytes_to_receive = 1;
                return Ok(());
            }
            SpiFlashInput::CsHigh => {
                if self.state.idle {
                    return Err(SpiFlashErr::CsChangeUnsupported);
                }

                let state_cleanup = |f: &mut SpiFlashImpl| {
                    f.state.idle = true;
                    f.state.address = 0;
                    f.state.dummy_cycles_needed = 0;
                    f.state.mode_clocks_needed = 0;
                    f.state.page_buffer.clear();
                    f.state.cmd = JedecSpiFlashCmd::Noop;
                    f.state.outbuffer.clear();
                };

                match self.state.cmd {
                    JedecSpiFlashCmd::PageProgram | JedecSpiFlashCmd::PageProgram4ba => {
                        self.perform_page_program();
                        // TODO need to wait
                        state_cleanup(self);
                        self.state.write_enable = false;

                        return Ok(());
                    }
                    JedecSpiFlashCmd::SectorErase
                    | JedecSpiFlashCmd::SectorErase4ba
                    | JedecSpiFlashCmd::BlockErase52
                    | JedecSpiFlashCmd::BlockErased8
                    | JedecSpiFlashCmd::BlockErasedc4ba
                    | JedecSpiFlashCmd::ChipErase60
                    | JedecSpiFlashCmd::ChipErasec7 => {
                        let ret = self.perform_erase();
                        state_cleanup(self);
                        self.state.write_enable = false;
                        match ret {
                            Ok(()) => return Ok(()),
                            Err(err) => return Err(err),
                        }
                    }
                    JedecSpiFlashCmd::Reset => {
                        if self.state.reset_enable {
                            self.state.reset_enable = false;
                            self.state.write_enable = false;
                            state_cleanup(self)
                        }
                    }
                    JedecSpiFlashCmd::WriteEnable => {
                        self.state.write_enable = true;
                        state_cleanup(self);
                        //                 self.state.status_write_enable = true; TODO on chips where it works like this
                    }
                    JedecSpiFlashCmd::WriteDisable => {
                        self.state.write_enable = false;
                        state_cleanup(self);
                    }
                    JedecSpiFlashCmd::Ewsr => {
                        self.state.status_write_enable = true;
                        state_cleanup(self);
                    }
                    JedecSpiFlashCmd::Enter4ba => {
                        self.state.four_bytes_address = true;
                        state_cleanup(self);
                    }
                    JedecSpiFlashCmd::Exit4ba => {
                        self.state.four_bytes_address = false;
                        state_cleanup(self);
                    }
                    JedecSpiFlashCmd::ResetEnable => {
                        self.state.reset_enable = true;
                        state_cleanup(self);
                    }
                    JedecSpiFlashCmd::Wrsr1 | JedecSpiFlashCmd::Wrsr2 | JedecSpiFlashCmd::Wrsr3 => {
                        let ret = self.perform_status_write();
                        self.state.status_write_enable = false;
                        state_cleanup(self);
                        match ret {
                            Ok(()) => return Ok(()),
                            Err(err) => return Err(err),
                        }
                    }
                    _ => (),
                }

                if self.state.bytes_to_receive == 0
                    && self.state.dummy_cycles_needed == 0
                    && self.state.mode_clocks_needed == 0
                {
                    state_cleanup(self);
                    return Ok(());
                }
                return Err(SpiFlashErr::CommandNotSuccessful);
            }
            SpiFlashInput::BytesSend(bytes) => {
                self.process_input_bytes(bytes)?;
            }
            SpiFlashInput::DummyCycles(cycles) => self.process_dummy(*cycles)?,
        };
        if self.state.dummy_cycles_needed == 0
            && self.state.bytes_to_receive == 0
            && self.state.mode_clocks_needed == 0
        {
            let output = self.process_output()?;
            if let Some(bytes) = output {
                self.state.outbuffer = bytes;
            }
        }
        Ok(())
    }

    /// Process time passing
    ///
    /// # arguments
    ///
    /// * `time` - u64
    ///
    /// * Err: SpiFlashErr
    /// * Ok(()):
    pub fn time_pass(&mut self, time: u64) -> Result<(), SpiFlashErr> {
        if !self.state.idle {
            return Err(SpiFlashErr::InvalidTimePassWhileNotIdle);
        }
        match self.state.busy {
            None => return Ok(()),
            Some(time_to_wait) => {
                if time >= time_to_wait {
                    self.state.busy = None;
                } else {
                    self.state.busy = Some(time_to_wait - time);
                }
            }
        }
        Ok(())
    }

    pub fn req_output(&mut self, req: SpiFlashOutReq) -> Result<Vec<u8>, SpiFlashErr> {
        if req.n_bytes == 0 {
            return Err(SpiFlashErr::BytesReqZeroBytes);
        }
        if self.state.outbuffer.is_empty() {
            return Err(SpiFlashErr::BytesReqNothingToSend);
        }
        // TODO figure out what to do when requesting too much later? It's not a problem
        // if self.state.outbuffer.len() < req.n_bytes {
        //     return Err(SpiFlashErr::BytesReqTooMuch);
        // }
        // Assume the output is always of the same type
        if self.state.outbuffer.first().unwrap().mode != req.mode {
            return Err(SpiFlashErr::BytesReqWrongMode);
        }
        let remain = self
            .state
            .outbuffer
            .split_off(req.n_bytes.try_into().unwrap());
        let to_send = self.state.outbuffer.iter().map(|x| x.byte).collect();
        self.state.outbuffer = remain;
        Ok(to_send)
    }
}

impl Default for SpiFlashImpl {
    fn default() -> Self {
        SpiFlashImpl::new("w25q01jv").unwrap()
    }
}

pub struct SpiFlash {
    flash: Rc<RefCell<SpiFlashImpl>>,
}
impl SpiFlash {
    pub fn new(name: &str) -> Option<Self> {
        let flash = SpiFlashImpl::new(name)?;
        Some(Self {
            flash: Rc::new(RefCell::new(flash)),
        })
    }

    /// Process input
    ///
    /// # arguments
    ///
    /// * `input` - SpiFlashInput
    ///
    /// #
    ///
    /// * Err: SpiFlashErr
    /// * Ok(()):
    pub fn input(&mut self, input: &SpiFlashInput) -> Result<(), SpiFlashErr> {
        let mut flash = self.flash.try_borrow_mut().unwrap();
        flash.input(input)
    }

    /// Request output
    ///
    /// # arguments
    ///
    /// * `input` - SpiFlashOutReq
    ///
    /// #
    /// * Err: SpiFlashErr
    /// * Ok: vec<u8>
    pub fn req_output(&mut self, req: SpiFlashOutReq) -> Result<Vec<u8>, SpiFlashErr> {
        let mut flash = self.flash.try_borrow_mut().unwrap();
        flash.req_output(req)
    }

    /// Process time passing
    ///
    /// # arguments
    ///
    /// * `time` - u64
    ///
    /// * Err: SpiFlashErr
    /// * Ok(()):
    pub fn time_pass(&mut self, time: u64) -> Result<(), SpiFlashErr> {
        let mut flash = self.flash.try_borrow_mut().unwrap();
        flash.time_pass(time)
    }
}
impl Default for SpiFlash {
    fn default() -> Self {
        Self::new("w25q01jv").unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_jedec_read_id() {
        let mut flash: SpiFlashImpl = Default::default();
        flash.input(&SpiFlashInput::CsLow).unwrap();

        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::Rdid)]);
        flash.input(&input).unwrap();
        assert_eq!(
            flash
                .req_output(SpiFlashOutReq {
                    mode: IoMode::Single,
                    n_bytes: 3
                })
                .unwrap(),
            vec![0xef, 0x40, 0x21]
        );

        flash.input(&SpiFlashInput::CsHigh).unwrap();
    }

    fn encode_cmd(cmd: JedecSpiFlashCmd) -> SpiByte {
        SpiByte {
            mode: IoMode::Single,
            byte: cmd.into(),
        }
    }

    fn encode_addr(addr: u32, four_ba: bool, mode: &IoMode) -> Vec<SpiByte> {
        let mut encoded_addr = Vec::new();
        let addr_size = if four_ba { 4 } else { 3 };

        for idx in 0..addr_size {
            let byte = (addr >> (8 * (addr_size - idx - 1)) & 0xff) as u8;
            encoded_addr.push(SpiByte { byte, mode: *mode });
        }

        encoded_addr
    }

    fn jedec_read(flash: &mut SpiFlashImpl, cmd: JedecSpiFlashCmd, addr: u32) -> u8 {
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::Rdsr3)]);
        flash.input(&input).unwrap();

        let four_ba_en = flash
            .req_output(SpiFlashOutReq {
                mode: IoMode::Single,
                n_bytes: 1,
            })
            .unwrap()
            .first()
            .unwrap()
            .bit(0);
        flash.input(&SpiFlashInput::CsHigh).unwrap();

        let (four_ba, input_mode, output_mode, dummy_cycles, mode_cycles) = match cmd {
            JedecSpiFlashCmd::Read => (four_ba_en, IoMode::Single, IoMode::Single, 0, 0),
            JedecSpiFlashCmd::Read4ba => (true, IoMode::Single, IoMode::Single, 0, 0),
            JedecSpiFlashCmd::FastRead => (four_ba_en, IoMode::Single, IoMode::Single, 8, 0),
            JedecSpiFlashCmd::FastRead4ba => (true, IoMode::Single, IoMode::Single, 8, 0),
            JedecSpiFlashCmd::FastReadDualOutput => {
                (four_ba_en, IoMode::Single, IoMode::Dual, 8, 0)
            }
            JedecSpiFlashCmd::FastReadDualOutput4ba => (true, IoMode::Single, IoMode::Dual, 8, 0),
            JedecSpiFlashCmd::FastReadDualIO => (four_ba_en, IoMode::Dual, IoMode::Dual, 4, 0),
            JedecSpiFlashCmd::FastReadDualIO4ba => (true, IoMode::Dual, IoMode::Dual, 4, 0),

            JedecSpiFlashCmd::FastReadQuadOutput => {
                (four_ba_en, IoMode::Single, IoMode::Quad, 8, 0)
            }
            JedecSpiFlashCmd::FastReadQuadOutput4ba => (true, IoMode::Single, IoMode::Quad, 8, 0),
            JedecSpiFlashCmd::FastReadQuadIO => (four_ba_en, IoMode::Quad, IoMode::Quad, 4, 2),
            JedecSpiFlashCmd::FastReadQuadIO4ba => (true, IoMode::Quad, IoMode::Quad, 4, 2),
            _ => panic!("Invalid CMD"),
        };

        flash.input(&SpiFlashInput::CsLow).unwrap();

        let mut seq = Vec::new();
        seq.push(encode_cmd(cmd));
        seq.append(&mut encode_addr(addr, four_ba, &input_mode));
        let cycles = match input_mode {
            IoMode::Single => 8,
            IoMode::Dual => 4,
            IoMode::Quad => 2,
        };
        for _ in 0..mode_cycles / cycles {
            seq.push(SpiByte {
                mode: input_mode,
                byte: 0xff,
            });
        }
        for _ in 0..dummy_cycles / cycles {
            seq.push(SpiByte {
                mode: input_mode,
                byte: 0xff,
            });
        }

        let input = SpiFlashInput::BytesSend(seq);
        flash.input(&input).unwrap();

        let output = flash
            .req_output(SpiFlashOutReq {
                mode: output_mode,
                n_bytes: 1,
            })
            .unwrap();

        let byte = output.first().unwrap();

        flash.input(&SpiFlashInput::CsHigh).unwrap();

        *byte
    }

    fn jedec_program_byte_4ba(flash: &mut SpiFlashImpl, addr: u32, byte: u8) {
        // Write enable latch
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::WriteEnable)]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();

        flash.input(&SpiFlashInput::CsLow).unwrap();

        // Read at address 0
        let mut seq = vec![SpiByte {
            mode: IoMode::Single,
            byte: JedecSpiFlashCmd::PageProgram.into(),
        }];

        seq.append(&mut encode_addr(addr, true, &IoMode::Single));
        seq.push(SpiByte {
            mode: IoMode::Single,
            byte,
        });
        let input = SpiFlashInput::BytesSend(seq);
        flash.input(&input).unwrap();

        flash.input(&SpiFlashInput::CsHigh).unwrap();
    }

    #[test]
    fn test_jedec_read_program_erase() {
        let mut flash: SpiFlashImpl = Default::default();

        // Enter 4ba
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::Enter4ba)]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();

        assert_eq!(jedec_read(&mut flash, JedecSpiFlashCmd::Read, 0), 0xff);

        jedec_program_byte_4ba(&mut flash, 0, 0xab);
        flash.time_pass(1000).unwrap();
        jedec_program_byte_4ba(&mut flash, 1, 0xab);
        flash.time_pass(1000).unwrap();
        assert_eq!(jedec_read(&mut flash, JedecSpiFlashCmd::Read, 1), 0xab);
        assert_eq!(jedec_read(&mut flash, JedecSpiFlashCmd::Read4ba, 1), 0xab);
        assert_eq!(jedec_read(&mut flash, JedecSpiFlashCmd::FastRead, 1), 0xab);
        assert_eq!(
            jedec_read(&mut flash, JedecSpiFlashCmd::FastRead4ba, 1),
            0xab
        );
        assert_eq!(
            jedec_read(&mut flash, JedecSpiFlashCmd::FastReadDualOutput, 1),
            0xab
        );
        assert_eq!(
            jedec_read(&mut flash, JedecSpiFlashCmd::FastReadDualOutput4ba, 1),
            0xab
        );
        assert_eq!(
            jedec_read(&mut flash, JedecSpiFlashCmd::FastReadDualIO, 1),
            0xab
        );
        assert_eq!(
            jedec_read(&mut flash, JedecSpiFlashCmd::FastReadDualIO4ba, 1),
            0xab
        );

        // Enable status write
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::Ewsr)]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();

        // Write status reg
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![
            encode_cmd(JedecSpiFlashCmd::Wrsr2),
            SpiByte {
                mode: IoMode::Single,
                byte: 0x02,
            },
        ]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();
        flash.time_pass(100).unwrap();

        // Write enable latch
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::WriteEnable)]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();

        // Erase whole chip
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::ChipErase60)]);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::CsHigh).unwrap();
        flash.time_pass(1000000).unwrap();
        assert_eq!(jedec_read(&mut flash, JedecSpiFlashCmd::Read, 1), 0xff);
    }

    #[test]
    fn test_jedec_sfdp() {
        let mut flash: SpiFlashImpl = Default::default();

        flash.input(&SpiFlashInput::CsLow).unwrap();
        let mut seq = vec![encode_cmd(JedecSpiFlashCmd::Sfdp)];
        seq.append(&mut encode_addr(0, false, &IoMode::Single));

        let input = SpiFlashInput::BytesSend(seq);
        flash.input(&input).unwrap();
        flash.input(&SpiFlashInput::DummyCycles(8)).unwrap();
        let output = flash
            .req_output(SpiFlashOutReq {
                mode: IoMode::Single,
                n_bytes: 256,
            })
            .unwrap();
        assert_eq!(output.as_slice(), SpiFlashImpl::SUPPORTED_FLASH[0].sfdp);

        flash.input(&SpiFlashInput::CsHigh).unwrap();
    }

    #[test]
    fn test_jecec_reset() {
        let mut flash: SpiFlashImpl = Default::default();
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::ResetEnable)]);
        flash.input(&input).unwrap();

        flash.input(&SpiFlashInput::CsHigh).unwrap();

        flash.input(&SpiFlashInput::CsLow).unwrap();
        let input = SpiFlashInput::BytesSend(vec![encode_cmd(JedecSpiFlashCmd::Reset)]);
        flash.input(&input).unwrap();

        flash.input(&SpiFlashInput::CsHigh).unwrap();
    }

    #[test]
    fn test_write_to_0x10_without_write_enable() {
        let mut flash: SpiFlashImpl = Default::default();

        // Try to write without enabling write first
        flash.input(&SpiFlashInput::CsLow).unwrap();
        let mut seq = vec![encode_cmd(JedecSpiFlashCmd::PageProgram)];

        // Set address 0x10
        seq.append(&mut encode_addr(0x10, false, &IoMode::Single));

        // Write 0xAB to address 0x10
        seq.push(SpiByte {
            mode: IoMode::Single,
            byte: 0xAB,
        });
        let input = SpiFlashInput::BytesSend(seq);
        assert!(matches!(
            flash.input(&input),
            Err(SpiFlashErr::WriteDisabled)
        ));

        assert_eq!(
            flash.input(&SpiFlashInput::CsHigh),
            Err(SpiFlashErr::CommandNotSuccessful)
        );
    }

    #[test]
    fn test_erase_0x10_without_write_enable() {
        let mut flash: SpiFlashImpl = Default::default();

        // Try to erase without enabling write first
        flash.input(&SpiFlashInput::CsLow).unwrap();

        // Set address 0x10 and attempt sector erase command
        let mut seq = vec![encode_cmd(JedecSpiFlashCmd::SectorErase)];
        seq.append(&mut encode_addr(0x10, false, &IoMode::Single));

        let input = SpiFlashInput::BytesSend(seq);
        assert_eq!(flash.input(&input), Err(SpiFlashErr::WriteDisabled));

        assert_eq!(
            flash.input(&SpiFlashInput::CsHigh),
            Err(SpiFlashErr::CommandNotSuccessful)
        );
    }
}
