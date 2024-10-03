/*++

Licensed under the Apache-2.0 license.

File Name:

    csr_file.rs

Abstract:

    File contains implementation of RISC-V Config and status register file

--*/

use std::rc::Rc;

use crate::internal_timers::InternalTimers;
use crate::types::{RvMIE, RvMPMC, RvMStatus, RvPmpAddrMode, RvPmpCfgi, RvPmpiCfg, RvPrivMode};
use crate::Pic;
use emulator_bus::{Clock, Timer, TimerAction};
use emulator_types::{RvAddr, RvData, RvException};

/// Configuration & Status Register
#[derive(Copy, Clone, Default)]
pub struct Csr {
    pub val: RvData,
    default_val: RvData,
    pub mask: u32,
}

pub enum MipBits {
    Mitip0 = 29,
    Mitip1 = 28,
}

impl Csr {
    /// ISA CSR
    pub const MISA: RvAddr = 0x301;

    /// Vendor ID CSR
    pub const MVENDORID: RvAddr = 0xF11;

    /// Architecture ID CSR
    pub const MARCHID: RvAddr = 0xF12;

    /// Implementation ID CSR
    pub const MIMPIID: RvAddr = 0xF13;

    /// HART ID CSR
    pub const MHARTID: RvAddr = 0xF14;

    /// HART Status CSR
    pub const MSTATUS: RvAddr = 0x300;

    /// Interrupt Enable CSR
    pub const MIE: RvAddr = 0x304;

    /// Interrupt Vector Table Address CSR
    pub const MTVEC: RvAddr = 0x305;

    /// Performance Counter Inhibit register CSR
    pub const MCOUNTINHIBIT: RvAddr = 0x320;

    /// Scratch Register CSR
    pub const MSCRATCH: RvAddr = 0x340;

    /// Exception Program Counter CSR
    pub const MEPC: RvAddr = 0x341;

    /// Exception Cause CSR
    pub const MCAUSE: RvAddr = 0x342;

    /// Exception Value CSR
    pub const MTVAL: RvAddr = 0x343;

    /// Interrupt Pending CSR
    pub const MIP: RvAddr = 0x344;

    /// Power management const CSR
    pub const MPMC: RvAddr = 0x7C6;

    /// Machine security configuration CSR
    pub const MSECCFG: RvAddr = 0x747;

    /// Cycle Low Counter CSR
    pub const MCYCLE: RvAddr = 0xB00;

    /// Instruction Retired Low Counter CSR
    pub const MINSTRET: RvAddr = 0xB02;

    /// Cycle High Counter CSR
    pub const MCYCLEH: RvAddr = 0xB80;

    /// Instruction Retired High Counter CSR
    pub const MINSTRETH: RvAddr = 0xB82;

    /// External Interrupt Vector Table CSR
    pub const MEIVT: RvAddr = 0xBC8;

    /// External Interrupt Handler Address Pointer CSR
    pub const MEIHAP: RvAddr = 0xFC8;

    /// Internal Timer Counter 0
    pub const MITCNT0: RvAddr = 0x7D2;

    /// Internal Timer Counter 1
    pub const MITCNT1: RvAddr = 0x7D5;

    /// Internal Timer Bound 0
    pub const MITB0: RvAddr = 0x7D3;

    /// Internal Timer Bound 1
    pub const MITB1: RvAddr = 0x7D6;

    /// Internal Timer Control 0
    pub const MITCTL0: RvAddr = 0x7D4;

    /// Internal Timer Control 0
    pub const MITCTL1: RvAddr = 0x7D5;

    /// PMP configuration register range start, inclusive
    pub const PMPCFG_START: RvAddr = 0x3A0;

    /// PMP configuration register range end, inclusive
    pub const PMPCFG_END: RvAddr = 0x3A3;

    /// PMP address register range start, inclusive
    pub const PMPADDR_START: RvAddr = 0x3B0;

    /// PMP address register range end, inclusive
    pub const PMPADDR_END: RvAddr = 0x3C0;

    /// Number of PMP address/cfg registers
    pub const PMPCOUNT: usize = 16;

    /// Create a new Configurations and Status register
    ///
    /// # Arguments
    ///
    /// * `default_val` - Reset value
    /// * `mask` - Write Mask
    pub fn new(default_val: RvData, mask: RvData) -> Self {
        Self {
            val: default_val,
            default_val,
            mask,
        }
    }

    pub fn reset(&mut self) -> &Self {
        self.val = self.default_val;
        self
    }
}

type CsrReadFn = fn(&CsrFile, RvPrivMode, RvAddr) -> Result<RvData, RvException>;
type CsrWriteFn = fn(&mut CsrFile, RvPrivMode, RvAddr, RvData) -> Result<(), RvException>;

/// CSR read/write functions
#[derive(Copy, Clone)]
struct CsrFn {
    /// CSR read function
    read_fn: CsrReadFn,

    /// CSR write function
    write_fn: CsrWriteFn,
}

impl CsrFn {
    /// Perform a CSR read
    ///
    /// # Arguments
    /// * `csr_file` - CSR file
    /// * `priv_mode` - Effective privilege mode
    /// * `addr` - CSR address to read from
    ///
    /// # Return
    ///
    /// * `RvData` - Register value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read(
        &self,
        csr_file: &CsrFile,
        priv_mode: RvPrivMode,
        addr: RvAddr,
    ) -> Result<RvData, RvException> {
        (self.read_fn)(csr_file, priv_mode, addr)
    }

    /// Perform a CSR write
    ///
    /// # Arguments
    /// * `csr_file` - CSR file
    /// * `priv_mode` - Effective privilege mode
    /// * `addr` - CSR address to write to
    /// * `val` - Data to write
    ///
    /// # Return
    ///
    /// * `RvData` - Register value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write(
        &self,
        csr_file: &mut CsrFile,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        (self.write_fn)(csr_file, priv_mode, addr, val)
    }
}

/// Configuration and status register file
pub struct CsrFile {
    /// CSRS
    csrs: Box<[Csr; CsrFile::CSR_COUNT]>,
    /// Timer
    timer: Timer,
    /// Maximum set PMPCFGi register
    max_pmpcfgi: Option<usize>,
    /// Internal Timers
    internal_timers: InternalTimers,
    /// Reference to PIC
    pic: Rc<Pic>,
}

/// Initalise a CSR read/write function in the CSR table
macro_rules! csr_fn {
    ($csrs:ident, $index:expr, $read_fn:path, $write_fn:path) => {
        // Because this is used in a constant expression, and write_fn is considered mutable,
        // a constructor can't be const. Therefore, we do it manually.
        $csrs[($index) as usize] = CsrFn {
            read_fn: $read_fn,
            write_fn: $write_fn,
        };
    };
}

/// Initialise the read/write functions of a block of CSRs in the CSR table
macro_rules! csr_fn_block {
    ($csrs:ident, $start:path, $end:path, $read_fn:path, $write_fn:path) => {
        let mut i = $start;
        // For loops aren't allowed in constant expressions; but loops are.
        loop {
            if i > $end {
                break;
            }
            csr_fn!($csrs, i, $read_fn, $write_fn);
            i += 1;
        }
    };
}

/// Initalise the default value and mask of a CSR
macro_rules! csr_val {
    ($csrs:ident, $index:expr, $default_val:literal, $mask:literal) => {
        $csrs[($index) as usize] = Csr::new($default_val, $mask);
    };
}

/// Initalise the default value and mask of a block of CSRs
macro_rules! csr_val_block {
    ($csrs:ident, $start:path, $end:path, $default_val:literal, $mask:literal) => {
        for i in ($start..=$end) {
            csr_val!($csrs, i, $default_val, $mask);
        }
    };
}

impl CsrFile {
    /// Supported CSR Count
    const CSR_COUNT: usize = 4096;

    /// CSR function table
    const CSR_FN: [CsrFn; CsrFile::CSR_COUNT] = {
        let default = CsrFn {
            read_fn: CsrFile::system_read,
            write_fn: CsrFile::system_write,
        };
        let mut table = [default; CsrFile::CSR_COUNT];

        csr_fn!(
            table,
            Csr::MSTATUS,
            CsrFile::system_read,
            CsrFile::mstatus_write
        );
        csr_fn!(table, Csr::MIP, CsrFile::mip_read, CsrFile::mip_write);
        csr_fn!(table, Csr::MIE, CsrFile::system_read, CsrFile::mie_write);
        csr_fn!(table, Csr::MPMC, CsrFile::system_read, CsrFile::mpmc_write);
        csr_fn!(
            table,
            Csr::MSECCFG,
            CsrFile::system_read,
            CsrFile::mseccfg_write
        );
        csr_fn!(
            table,
            Csr::MEIVT,
            CsrFile::system_read,
            CsrFile::meivt_write
        );
        csr_fn_block!(
            table,
            Csr::PMPCFG_START,
            Csr::PMPCFG_END,
            CsrFile::system_read,
            CsrFile::pmpcfg_write
        );
        csr_fn_block!(
            table,
            Csr::PMPADDR_START,
            Csr::PMPADDR_END,
            CsrFile::system_read,
            CsrFile::pmpaddr_write
        );

        // internal timer registers
        csr_fn!(
            table,
            Csr::MITCNT0,
            CsrFile::mitcnt_read,
            CsrFile::mitcnt_write
        );
        csr_fn!(
            table,
            Csr::MITCNT1,
            CsrFile::mitcnt_read,
            CsrFile::mitcnt_write
        );
        csr_fn!(table, Csr::MITB0, CsrFile::mitb_read, CsrFile::mitb_write);
        csr_fn!(table, Csr::MITB1, CsrFile::mitb_read, CsrFile::mitb_write);
        csr_fn!(
            table,
            Csr::MITCTL0,
            CsrFile::mitctl_read,
            CsrFile::mitctl_write
        );
        csr_fn!(
            table,
            Csr::MITCTL1,
            CsrFile::mitctl_read,
            CsrFile::mitctl_write
        );
        csr_fn!(
            table,
            Csr::MEIHAP,
            CsrFile::meihap_read,
            CsrFile::system_write
        );

        table
    };

    /// Create a new Configuration and status register file
    pub fn new(clock: Rc<Clock>, pic: Rc<Pic>) -> Self {
        let mut csrs = Box::new([Csr::default(); CsrFile::CSR_COUNT]);

        csr_val!(csrs, Csr::MISA, 0x4010_1104, 0x0000_0000);
        csr_val!(csrs, Csr::MVENDORID, 0x0000_0045, 0x0000_0000);
        csr_val!(csrs, Csr::MARCHID, 0x0000_0010, 0x0000_0000);
        csr_val!(csrs, Csr::MIMPIID, 0x0000_0004, 0x0000_0000);
        csr_val!(csrs, Csr::MHARTID, 0x0000_0000, 0x0000_0000);
        csr_val!(csrs, Csr::MSTATUS, 0x1800_1800, 0x0002_1888);
        csr_val!(csrs, Csr::MIE, 0x0000_0000, 0x7000_0888);
        csr_val!(csrs, Csr::MTVEC, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MCOUNTINHIBIT, 0x0000_0000, 0x0000_007D);
        csr_val!(csrs, Csr::MSCRATCH, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MEPC, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MCAUSE, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MTVAL, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MPMC, 0x0000_0002, 0x0000_0002);
        csr_val!(csrs, Csr::MSECCFG, 0x0000_0000, 0x0000_0003);
        csr_val!(csrs, Csr::MCYCLE, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MCYCLEH, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MINSTRET, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MINSTRETH, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MEIVT, 0x0000_0000, 0xFFFF_FC00);
        csr_val_block!(
            csrs,
            Csr::PMPCFG_START,
            Csr::PMPCFG_END,
            0x0000_0000,
            0x9F9F_9F9F
        );
        csr_val_block!(
            csrs,
            Csr::PMPADDR_START,
            Csr::PMPADDR_END,
            0x0000_0000,
            0x3FFF_FFFF
        );
        csr_val!(csrs, Csr::MITCNT0, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MITCNT1, 0x0000_0000, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MITB0, 0xFFFF_FFFF, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MITB1, 0xFFFF_FFFF, 0xFFFF_FFFF);
        csr_val!(csrs, Csr::MITCTL0, 0x0000_0001, 0x0000_000F);
        csr_val!(csrs, Csr::MITCTL1, 0x0000_0001, 0x0000_000F);

        Self {
            csrs,
            timer: Timer::new(&clock),
            max_pmpcfgi: None,
            internal_timers: crate::internal_timers::InternalTimers::new(clock.clone()),
            pic,
        }
    }

    /// Reset the CSR file
    pub fn reset(&mut self) {
        for csr in self.csrs.iter_mut() {
            csr.reset();
        }
        self.max_pmpcfgi = None;
    }

    /// Allow all reads from the given CSR
    fn any_read(&self, _: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        Ok(self.csrs[addr as usize].val)
    }

    /// Allow all writes to the given CSR, taking into account the mask
    fn any_write(&mut self, _: RvPrivMode, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        let csr = &mut self.csrs[addr as usize];
        csr.val = (csr.val & !csr.mask) | (val & csr.mask);
        Ok(())
    }

    /// Allow only system reads from the given CSR
    fn system_read(&self, priv_mode: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        if priv_mode == RvPrivMode::U {
            return Err(RvException::illegal_register());
        }

        self.any_read(priv_mode, addr)
    }

    /// Allow only system writes to the given CSR
    fn system_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mode == RvPrivMode::U {
            return Err(RvException::illegal_register());
        }

        self.any_write(priv_mode, addr, val)
    }

    fn meihap_read(&self, priv_mode: RvPrivMode, _: RvAddr) -> Result<RvData, RvException> {
        if priv_mode == RvPrivMode::U {
            return Err(RvException::illegal_register());
        }
        self.system_read(RvPrivMode::M, Csr::MEIVT)
            .map(|v| v + ((self.pic.highest_priority_irq_total().unwrap_or(0) as u32) << 2))
    }

    /// Perform a write to the MEIVT CSR
    fn meivt_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        //println!("Setting MEIVT to {:x}", val);
        self.system_write(priv_mode, addr, val)?;
        let csr = self.csrs[addr as usize];
        self.timer
            .schedule_action_in(0, TimerAction::SetExtIntVec { addr: csr.val });
        Ok(())
    }

    /// Perform a write to the MSTATUS CSR
    fn mstatus_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        // Write new mstatus value
        let csr = self.csrs[addr as usize];
        let mstatus_old = RvMStatus(csr.val);
        let mut mstatus_new = RvMStatus(val);
        if mstatus_new.mpp() == RvPrivMode::Invalid {
            // Ignore invalid write
            mstatus_new.set_mpp(mstatus_old.mpp());
        }
        self.system_write(priv_mode, addr, mstatus_new.0)?;

        // Read back mstatus register after masking
        let csr = self.csrs[addr as usize];
        let mstatus_new = RvMStatus(csr.val);
        self.timer.schedule_action_in(
            0,
            TimerAction::SetGlobalIntEn {
                en: mstatus_new.mie() == 1,
            },
        );
        // Let's see if the soc wants to interrupt
        self.timer.schedule_poll_in(2);
        Ok(())
    }

    /// Perform a read of the MIP CSR.
    fn mip_read(&self, priv_mode: RvPrivMode, _: RvAddr) -> Result<RvData, RvException> {
        if priv_mode == RvPrivMode::U {
            return Err(RvException::illegal_register());
        }

        let mie = self.system_read(priv_mode, Csr::MIE)?;
        let (mitip0, mitip1) = self.internal_timers.interrupts_pending();
        let mitip0 = if mitip0 {
            1 << MipBits::Mitip0 as RvData
        } else {
            0
        };
        let mitip1 = if mitip1 {
            1 << MipBits::Mitip1 as RvData
        } else {
            0
        };
        let val = mie & (mitip0 | mitip1);
        Ok(val)
    }

    /// Perform a (no-op) write to the MIP CSR.
    fn mip_write(
        &mut self,
        priv_mode: RvPrivMode,
        _: RvAddr,
        _: RvData,
    ) -> Result<(), RvException> {
        if priv_mode == RvPrivMode::U {
            return Err(RvException::illegal_register());
        }
        // do nothing as this is a read-only register
        Ok(())
    }

    /// Perform a write to the MIE CSR
    fn mie_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        self.system_write(priv_mode, addr, val)?;
        let csr = self.csrs[addr as usize];
        let mie = RvMIE(csr.val);
        self.timer.schedule_action_in(
            0,
            TimerAction::SetExtIntEn {
                en: mie.meie() == 1,
            },
        );
        // Let's see if the soc wants to interrupt
        self.timer.schedule_poll_in(2);
        Ok(())
    }

    /// Perform a write to the MPMC CSR
    fn mpmc_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        self.system_write(priv_mode, addr, val)?;
        let csr = self.csrs[addr as usize];
        let mpmc_write = RvMPMC(val);
        if mpmc_write.halt() == 1 {
            let mpcm = RvMPMC(csr.val);
            if mpcm.haltie() == 1 {
                let mut mstatus = RvMStatus(self.read(priv_mode, Csr::MSTATUS)?);
                mstatus.set_mie(1);
                self.write(priv_mode, Csr::MSTATUS, mstatus.0)?;
            }
            self.timer.schedule_action_in(0, TimerAction::Halt);
        }
        Ok(())
    }

    /// Perform a write to the MSECCFG register
    fn mseccfg_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }

        let csr = self.csrs[addr as usize];

        // All current bits are sticky
        let val = val | csr.val;
        self.any_write(priv_mode, addr, val)
    }

    /// Perform a write to a PMPCFG CSR
    fn pmpcfg_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }

        // Locate the specific packed PMP config register
        let mut pmpcfgi = RvPmpCfgi(self.read(priv_mode, addr)?);

        // None: no change
        // Some(true): is set
        // Some(false): is unset
        let mut is_set: Option<bool> = None;

        // Do not write if the entry is locked
        if pmpcfgi.r1().lock() == 0 {
            let val = (val & 0xFF) as u8;
            is_set = Some(val > 0);
            pmpcfgi.set_r1(RvPmpiCfg(val));
        }
        if pmpcfgi.r2().lock() == 0 {
            let val = ((val >> 8) & 0xFF) as u8;
            if is_set.is_none() || is_set == Some(false) {
                is_set = Some(val > 0);
            }
            pmpcfgi.set_r2(RvPmpiCfg(val));
        }
        if pmpcfgi.r3().lock() == 0 {
            let val = ((val >> 16) & 0xFF) as u8;
            if is_set.is_none() || is_set == Some(false) {
                is_set = Some(val > 0);
            }
            pmpcfgi.set_r3(RvPmpiCfg(val));
        }
        if pmpcfgi.r4().lock() == 0 {
            let val = ((val >> 24) & 0xFF) as u8;
            if is_set.is_none() || is_set == Some(false) {
                is_set = Some(val > 0);
            }
            pmpcfgi.set_r4(RvPmpiCfg(val));
        }

        let index = (addr - Csr::PMPCFG_START) as usize;
        match is_set {
            Some(true) => {
                // New highest index?
                if self.max_pmpcfgi.is_none() || self.max_pmpcfgi < Some(index) {
                    self.max_pmpcfgi = Some(index);
                }
            }
            Some(false) => {
                // Was this the highest index?
                if self.max_pmpcfgi == Some(index) {
                    // Find new highest index, or fall back to None
                    self.max_pmpcfgi = None;
                    for i in (0..index).rev() {
                        if self.any_read(RvPrivMode::M, Csr::PMPCFG_START + i as RvAddr)? > 0 {
                            self.max_pmpcfgi = Some(i);
                            break;
                        }
                    }
                }
            }
            _ => return Ok(()),
        }

        self.any_write(priv_mode, addr, pmpcfgi.0)
    }

    /// Perform a write to a PMPADDR register
    fn pmpaddr_write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }

        // Find corresponding pmpcfg register
        let index: usize = (addr - Csr::PMPADDR_START) as usize;
        let mut pmpicfg = self.read_pmpicfg(index)?;
        if pmpicfg.lock() != 0 {
            // Ignore the write
            return Ok(());
        }

        // If pmpicfg is TOR, writes to pmpaddri-1 are ignored
        // Therefore, check pmpi+1cfg, which corresponds to pmpaddri
        if index < (Csr::PMPCOUNT - 1) {
            pmpicfg = self.read_pmpicfg(index + 1)?;
            if pmpicfg.addr_mode() == RvPmpAddrMode::Tor && pmpicfg.lock() != 0 {
                // Ignore the write
                return Ok(());
            }
        }

        self.any_write(priv_mode, addr, val)
    }

    /// Read the specified PMPiCFG status register
    ///
    /// # Arguments
    ///
    /// * `reg` - PMP configuration register to read
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    fn read_pmpicfg(&self, reg: usize) -> Result<RvPmpiCfg, RvException> {
        // Find corresponding pmpcfg register
        let pmpcfgi_index = (reg / 4) as RvAddr + Csr::PMPCFG_START;
        let pmpcfg_offset = reg % 4;
        let pmpcfgi = RvPmpCfgi(self.any_read(RvPrivMode::M, pmpcfgi_index)?);
        let result = match pmpcfg_offset {
            0 => pmpcfgi.r1(),
            1 => pmpcfgi.r2(),
            2 => pmpcfgi.r3(),
            3 => pmpcfgi.r4(),
            _ => unreachable!(),
        };
        Ok(result)
    }

    /// Check if an address matches against one PMP register.
    /// Return the first configuration register that does, or None.
    ///
    /// This function performs no other checks.
    ///
    /// # Arguments
    ///
    /// * `pmpicfg` - PMPiCFG register to check
    /// * `index` - index of PMPADDR register to check
    /// * `addr` - Address to check
    ///
    /// # Return
    ///
    /// * `true` if PMP entry matches, otherwise `false`
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    fn pmp_match_one_addr(
        &self,
        pmpicfg: RvPmpiCfg,
        index: usize,
        addr: RvAddr,
    ) -> Result<bool, RvException> {
        let addr_mode = pmpicfg.addr_mode();
        if addr_mode == RvPmpAddrMode::Off {
            // No need for additional checks
            return Ok(false);
        }

        let pmpaddr = self.any_read(RvPrivMode::M, Csr::PMPADDR_START + index as RvAddr)?;
        let pmpaddr_shift = pmpaddr << 2;
        let addr_top;
        let addr_bottom;

        match addr_mode {
            RvPmpAddrMode::Tor => {
                // Bottom address is 0 if this register is 0
                // otherwise it's the previous one
                addr_top = pmpaddr_shift;
                addr_bottom = if index > 0 {
                    self.any_read(RvPrivMode::M, Csr::PMPADDR_START + (index - 1) as RvAddr)? << 2
                } else {
                    0
                };
            }
            RvPmpAddrMode::Na4 => {
                // Four-byte range
                addr_top = pmpaddr_shift + 4;
                addr_bottom = pmpaddr_shift;
            }
            RvPmpAddrMode::Napot => {
                // Range from 8..32
                addr_top = pmpaddr_shift + (1 << (pmpaddr.trailing_ones() + 3));
                addr_bottom = pmpaddr_shift;
            }
            _ => unreachable!(),
        }

        Ok(addr >= addr_bottom && addr < addr_top)
    }

    /// Check if an address matches against the PMP registers.
    /// Return the first configuration register that does, or None.
    ///
    /// This function performs no other checks.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to check
    ///
    /// # Return
    ///
    /// * `RvPmpCfg` - Configuration value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn pmp_match_addr(&self, addr: RvAddr) -> Result<Option<RvPmpiCfg>, RvException> {
        let max_pmpcfgi = match self.max_pmpcfgi {
            // Optimisation: ignore PMP if no registers are set
            None => return Ok(None),
            Some(val) => val,
        };

        for i in 0..=max_pmpcfgi {
            let pmpcfgi = RvPmpCfgi(self.any_read(RvPrivMode::M, Csr::PMPCFG_START + i as RvAddr)?);

            let pmpicfg_1 = pmpcfgi.r1();
            let pmpicfg_2 = pmpcfgi.r2();
            let pmpicfg_3 = pmpcfgi.r3();
            let pmpicfg_4 = pmpcfgi.r4();

            // Check packed registers
            if self.pmp_match_one_addr(pmpicfg_1, i * 4, addr)? {
                return Ok(Some(pmpicfg_1));
            } else if self.pmp_match_one_addr(pmpicfg_2, (i * 4) + 1, addr)? {
                return Ok(Some(pmpicfg_2));
            } else if self.pmp_match_one_addr(pmpicfg_3, (i * 4) + 2, addr)? {
                return Ok(Some(pmpicfg_3));
            } else if self.pmp_match_one_addr(pmpicfg_4, (i * 4) + 3, addr)? {
                return Ok(Some(pmpicfg_4));
            }
        }

        Ok(None)
    }

    fn mitcnt_read(&self, priv_mode: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITCNT0 => Ok(self.internal_timers.read_mitcnt0()),
            Csr::MITCNT1 => Ok(self.internal_timers.read_mitcnt1()),
            _ => unreachable!(),
        }
    }

    fn mitcnt_write(
        &mut self,
        priv_mod: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mod != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITCNT0 => self.internal_timers.write_mitcnt0(val),
            Csr::MITCNT1 => self.internal_timers.write_mitcnt1(val),
            _ => unreachable!(),
        };
        Ok(())
    }

    fn mitb_read(&self, priv_mode: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITB0 => Ok(self.internal_timers.read_mitb0()),
            Csr::MITB1 => Ok(self.internal_timers.read_mitb1()),
            _ => unreachable!(),
        }
    }

    fn mitb_write(
        &mut self,
        priv_mod: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mod != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITB0 => self.internal_timers.write_mitb0(val),
            Csr::MITB1 => self.internal_timers.write_mitb1(val),
            _ => unreachable!(),
        };
        Ok(())
    }

    fn mitctl_read(&self, priv_mode: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        if priv_mode != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITCTL0 => Ok(self.internal_timers.read_mitctl0()),
            Csr::MITCTL1 => Ok(self.internal_timers.read_mitctl1()),
            _ => unreachable!(),
        }
    }

    fn mitctl_write(
        &mut self,
        priv_mod: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        if priv_mod != RvPrivMode::M {
            return Err(RvException::illegal_register());
        }
        match addr {
            Csr::MITCTL0 => self.internal_timers.write_mitctl0(val),
            Csr::MITCTL1 => self.internal_timers.write_mitctl1(val),
            _ => unreachable!(),
        }
        Ok(())
    }

    /// Read the specified configuration status register, taking into account the privilege mode
    ///
    /// # Arguments
    ///
    /// * `priv_mode` - Privilege mode
    /// * `csr` - Configuration status register to read
    ///
    ///  # Return
    ///
    ///  * `RvData` - Register value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister``
    pub fn read(&self, priv_mode: RvPrivMode, addr: RvAddr) -> Result<RvData, RvException> {
        const CSR_MAX: usize = CsrFile::CSR_COUNT - 1;
        if addr as usize > CSR_MAX {
            return Err(RvException::illegal_register());
        }

        Self::CSR_FN[addr as usize].read(self, priv_mode, addr)
    }

    /// Write the specified Configuration status register, taking into account the privilege mode
    ///
    /// # Arguments
    ///
    /// * `priv_mode` - Privilege mode
    /// * `reg` - Configuration  status register to write
    /// * `val` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write(
        &mut self,
        priv_mode: RvPrivMode,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        const CSR_MAX: usize = CsrFile::CSR_COUNT - 1;
        if addr as usize > CSR_MAX {
            return Err(RvException::illegal_register());
        }

        Self::CSR_FN[addr as usize].write(self, priv_mode, addr, val)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::rc::Rc;

    #[test]
    fn test_u_mode_read_m_mode_csr() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let csrs = CsrFile::new(clock, pic);

        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::MSTATUS).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::MISA).err(),
            Some(RvException::illegal_register())
        );
    }

    #[test]
    fn test_u_mode_write_m_mode_csr() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::MSTATUS, 0xFFFF_FFFF).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::MISA, 0xFFFF_FFFF).err(),
            Some(RvException::illegal_register())
        );
    }

    #[test]
    fn test_u_mode_read_write_pmp() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::PMPCFG_START, 0xFFFF_FFFF)
                .err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::PMPCFG_START).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::PMPADDR_START, 0xFFFF_FFFF)
                .err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::PMPADDR_START).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::PMPCFG_END, 0xFFFF_FFFF)
                .err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::PMPCFG_END).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_END).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::U, Csr::PMPADDR_END, 0xFFFF_FFFF)
                .err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::U, Csr::PMPADDR_END).err(),
            Some(RvException::illegal_register())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_END).ok(),
            Some(0x0000_0000)
        );
    }

    #[test]
    fn test_m_mode_read_write_pmp() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x1717_1717)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x1717_1717)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START).ok(),
            Some(0x3FFF_FFFF)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_END, 0x1717_1717).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_END).ok(),
            Some(0x1717_1717)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_END, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_END).ok(),
            Some(0x3FFF_FFFF)
        );
    }

    #[test]
    fn test_lock_pmp() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        // Lock PMPADDR1, but not PMPADDR0, 2, or 3.
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0000_8000)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0000_8000)
        );

        // PMP0CFG, PMP2CFG, and PMP3CFG should be writable, but not PMP1CFG
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0000_8001)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0000_8001)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0000_8101)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0000_8001)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0001_8101)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0001_8001)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0101_8101)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPCFG_START).ok(),
            Some(0x0101_8001)
        );

        // PMPADDR0, 2, and 3 should be writable, but not PMPADDR1
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START).ok(),
            Some(0x3FFF_FFFF)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 1, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 1).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 2, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 2).ok(),
            Some(0x3FFF_FFFF)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 3, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 3).ok(),
            Some(0x3FFF_FFFF)
        );
    }

    #[test]
    fn test_pmp_tor_lock() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        // Set PMP2CFG to TOR and lock
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPCFG_START, 0x0000_8800)
                .ok(),
            Some(())
        );

        // Writes to PMPADDR1 and 2 should be ignored, but not PMPADDR3 or PMPADDR4
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 1, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 1).ok(),
            Some(0x0000_0000)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 2, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 2).ok(),
            Some(0x3FFF_FFFF)
        );

        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::PMPADDR_START + 3, 0xFFFF_FFFF)
                .ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::PMPADDR_START + 3).ok(),
            Some(0x3FFF_FFFF)
        );
    }

    #[test]
    fn test_read_only_csr() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        assert_eq!(csrs.read(RvPrivMode::M, Csr::MISA).ok(), Some(0x4010_1104));
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MISA, u32::MAX).ok(),
            Some(())
        );
        assert_eq!(csrs.read(RvPrivMode::M, Csr::MISA).ok(), Some(0x4010_1104));
    }

    #[test]
    fn test_read_write_csr() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);
        assert_eq!(csrs.read(RvPrivMode::M, Csr::MEPC).ok(), Some(0));
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MEPC, u32::MAX).ok(),
            Some(())
        );
        assert_eq!(csrs.read(RvPrivMode::M, Csr::MEPC).ok(), Some(u32::MAX));
    }

    #[test]
    fn test_mseccfg_csr_sticky() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSECCFG, 0xFFFF_FFFF).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSECCFG).ok(),
            Some(0x0000_0003)
        );
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSECCFG, 0x0000_0000).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSECCFG).ok(),
            Some(0x0000_0003)
        );
    }

    #[test]
    fn test_mstatus_invalid_mpp() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSTATUS, 0x0000_1800).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSTATUS).ok(),
            Some(0x1800_1800)
        );
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSTATUS, 0x0000_0800).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSTATUS).ok(),
            Some(0x1800_1800)
        );
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSTATUS, 0x0000_0000).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSTATUS).ok(),
            Some(0x1800_0000)
        );
    }

    #[test]
    fn test_read_write_masked_csr() {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut csrs = CsrFile::new(clock, pic);

        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSTATUS).ok(),
            Some(0x1800_1800)
        );
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MSTATUS, u32::MAX).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MSTATUS).ok(),
            Some(0x1802_1888)
        );

        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MCOUNTINHIBIT).ok(),
            Some(0x0000_0000)
        );
        assert_eq!(
            csrs.write(RvPrivMode::M, Csr::MCOUNTINHIBIT, u32::MAX).ok(),
            Some(())
        );
        assert_eq!(
            csrs.read(RvPrivMode::M, Csr::MCOUNTINHIBIT).ok(),
            Some(0x0000_007D)
        );
    }
}