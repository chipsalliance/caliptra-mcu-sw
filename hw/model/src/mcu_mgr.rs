// Licensed under the Apache-2.0 license

use ureg::MmioMut;

pub trait McuManager {
    const I3C_ADDR: u32;
    const MCI_ADDR: u32;
    const TRACE_BUFFER_ADDR: u32;
    const MBOX_0_ADDR: u32;
    const MBOX_1_ADDR: u32;
    const MCU_SRAM_ADDR: u32;
    const OTP_CTRL_ADDR: u32;
    const LC_CTRL_ADDR: u32;

    type TMmio<'a>: MmioMut
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_>;

    /// A register block that can be used to manipulate the i3c peripheral
    fn i3c(&mut self) -> caliptra_registers::i3ccsr::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::i3ccsr::RegisterBlock::new_with_mmio(
                Self::I3C_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mci peripheral
    fn mci(&mut self) -> caliptra_registers::mci::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mci::RegisterBlock::new_with_mmio(
                Self::MCI_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mcu_trace_buffer peripheral
    fn trace_buffer(
        &mut self,
    ) -> caliptra_registers::mcu_trace_buffer::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mcu_trace_buffer::RegisterBlock::new_with_mmio(
                Self::TRACE_BUFFER_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mcu_mbox0 peripheral
    fn mbox0(&mut self) -> caliptra_registers::mcu_mbox0::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mcu_mbox0::RegisterBlock::new_with_mmio(
                Self::MBOX_0_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mcu_mbox1 peripheral
    fn mbox1(&mut self) -> caliptra_registers::mcu_mbox1::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mcu_mbox1::RegisterBlock::new_with_mmio(
                Self::MBOX_1_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mcu_sram peripheral
    fn mcu_sram(&mut self) -> caliptra_registers::mcu_sram::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mcu_sram::RegisterBlock::new_with_mmio(
                Self::MCU_SRAM_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the otp_ctrl peripheral
    fn otp_ctrl(&mut self) -> caliptra_registers::otp_ctrl::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::otp_ctrl::RegisterBlock::new_with_mmio(
                Self::OTP_CTRL_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the lc_ctrl peripheral
    fn lc_ctrl(&mut self) -> caliptra_registers::lc_ctrl::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::lc_ctrl::RegisterBlock::new_with_mmio(
                Self::LC_CTRL_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    fn with_regs<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        f(self)
    }

    fn with_i3c<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::i3ccsr::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.i3c())
    }

    fn with_mci<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::mci::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.mci())
    }

    fn with_trace_buffer<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::mcu_trace_buffer::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.trace_buffer())
    }

    fn with_mbox0<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::mcu_mbox0::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.mbox0())
    }

    fn with_mbox1<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::mcu_mbox1::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.mbox1())
    }

    fn with_mcu_sram<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::mcu_sram::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.mcu_sram())
    }

    fn with_otp<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::otp_ctrl::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.otp_ctrl())
    }

    fn with_lc<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(caliptra_registers::lc_ctrl::RegisterBlock<Self::TMmio<'_>>) -> T,
    {
        f(self.lc_ctrl())
    }
}
