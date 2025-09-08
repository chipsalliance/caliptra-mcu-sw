// Licensed under the Apache-2.0 license

#![allow(clippy::mut_from_ref)]

use crate::{InitParams, McuHwModel, McuManager};
use anyhow::{bail, Result};
use caliptra_api::SocManager;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Event};
use caliptra_emu_periph::MailboxRequester;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model::{
    DeviceLifecycle, HwModel, InitParams as CaliptraInitParams, ModelFpgaSubsystem, Output,
    SecurityState,
};
use caliptra_registers::i3ccsr::regs::StbyCrDeviceAddrWriteVal;
use mcu_rom_common::LifecycleControllerState;
use std::io::Write;
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::mpsc;
use tock_registers::interfaces::{Readable, Writeable};

const DEFAULT_AXI_PAUSER: u32 = 0x1;

struct CaliptraMmio {
    ptr: *mut u32,
}

impl CaliptraMmio {
    #[allow(unused)]
    fn mbox(&self) -> &mut registers_generated::mbox::regs::Mbox {
        unsafe {
            &mut *(self.ptr.offset(0x2_0000 / 4) as *mut registers_generated::mbox::regs::Mbox)
        }
    }
    #[allow(unused)]
    fn soc(&self) -> &mut registers_generated::soc::regs::Soc {
        unsafe { &mut *(self.ptr.offset(0x3_0000 / 4) as *mut registers_generated::soc::regs::Soc) }
    }
}

pub struct ModelFpgaRealtime {
    base: ModelFpgaSubsystem,

    openocd: Option<TcpStream>,
}

impl ModelFpgaRealtime {
    pub fn i3c_target_configured(&mut self) -> bool {
        self.base.i3c_target_configured()
    }

    pub fn configure_i3c_controller(&mut self) {
        self.base.i3c_controller.configure()
    }

    pub fn start_recovery_bmc(&mut self) {
        self.base.start_recovery_bmc();
    }

    // send a recovery block write request to the I3C target
    pub fn send_i3c_write(&mut self, payload: &[u8]) {
        self.base.i3c_controller.write(payload).unwrap();
    }

    pub fn recv_i3c(&mut self, len: u16) -> Vec<u8> {
        self.base.i3c_controller.read(len).unwrap()
    }

    pub fn open_openocd(&mut self, port: u16) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr)?;
        self.openocd = Some(stream);
        Ok(())
    }

    pub fn close_openocd(&mut self) {
        self.openocd.take();
    }

    pub fn set_uds_req(&mut self) -> Result<()> {
        let Some(mut socket) = self.openocd.take() else {
            bail!("openocd socket is not open");
        };

        socket.write_all("riscv.cpu riscv dmi_write 0x70 4\n".as_bytes())?;

        self.openocd = Some(socket);
        Ok(())
    }

    pub fn set_bootfsm_go(&mut self) -> Result<()> {
        let Some(mut socket) = self.openocd.take() else {
            bail!("openocd socket is not open");
        };

        socket.write_all("riscv.cpu riscv dmi_write 0x61 1\n".as_bytes())?;

        self.openocd = Some(socket);
        Ok(())
    }

    fn caliptra_axi_bus(&mut self) -> FpgaRealtimeBus<'_> {
        FpgaRealtimeBus {
            caliptra_mmio: self.base.caliptra_mmio,
            i3c_mmio: self.base.i3c_mmio,
            mci_mmio: self.base.mci.ptr,
            otp_mmio: self.base.otp_mmio,
            lc_mmio: self.base.lc_mmio,
            phantom: Default::default(),
        }
    }
}

impl McuHwModel for ModelFpgaRealtime {
    fn step(&mut self) {
        self.base.step();
    }

    fn new_unbooted(params: InitParams) -> Result<Self>
    where
        Self: Sized,
    {
        println!("ModelFpgaRealtime::new_unbooted");

        let security_state_unprovisioned = SecurityState::default();
        let security_state_manufacturing =
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
        let security_state_prod =
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Production);

        let security_state = match params
            .lifecycle_controller_state
            .unwrap_or(LifecycleControllerState::Raw)
        {
            LifecycleControllerState::Prod | LifecycleControllerState::ProdEnd => {
                security_state_prod
            }
            LifecycleControllerState::Dev => security_state_manufacturing,
            _ => security_state_unprovisioned,
        };

        let cptra_init = CaliptraInitParams {
            rom: params.caliptra_rom,
            dccm: params.caliptra_dccm,
            iccm: params.caliptra_iccm,
            log_writer: params.log_writer,
            security_state,
            dbg_manuf_service: params.dbg_manuf_service,
            subsystem_mode: true,
            uds_granularity_64: !params.uds_granularity_32,
            prod_dbg_unlock_keypairs: params.prod_dbg_unlock_keypairs,
            debug_intent: params.debug_intent,
            cptra_obf_key: params.cptra_obf_key,
            csr_hmac_key: params.csr_hmac_key,
            itrng_nibbles: params.itrng_nibbles,
            etrng_responses: params.etrng_responses,
            trng_mode: Some(caliptra_hw_model::TrngMode::Internal),
            random_sram_puf: params.random_sram_puf,
            trace_path: params.trace_path,
            stack_info: params.stack_info,
            soc_user: MailboxRequester::SocUser(DEFAULT_AXI_PAUSER),
            test_sram: None,
            mcu_rom: Some(params.mcu_rom),
            enable_mcu_uart_log: true,
        };
        println!("Starting base model");
        let base = ModelFpgaSubsystem::new_unbooted(cptra_init)
            .map_err(|e| anyhow::anyhow!("Failed to initialized base model: {e}"))?;

        let m = Self {
            base,

            openocd: None,
        };

        Ok(m)
    }

    fn boot(&mut self, boot_params: caliptra_hw_model::BootParams) -> Result<()>
    where
        Self: Sized,
    {
        self.base
            .boot(boot_params)
            .map_err(|e| anyhow::anyhow!("Failed to boot: {e}"))?;
        Ok(())
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaRealtime"
    }

    fn output(&mut self) -> &mut Output {
        self.base.output()
    }

    fn ready_for_fw(&self) -> bool {
        true
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }

    fn set_axi_user(&mut self, pauser: u32) {
        self.base.wrapper.regs().arm_user.set(pauser);
        self.base.wrapper.regs().lsu_user.set(pauser);
        self.base.wrapper.regs().ifu_user.set(pauser);
        self.base.wrapper.regs().dma_axi_user.set(pauser);
        self.base.wrapper.regs().soc_config_user.set(pauser);
        self.base.wrapper.regs().sram_config_user.set(pauser);
    }

    fn set_caliptra_boot_go(&mut self, go: bool) {
        self.base.mci.regs().cptra_boot_go().write(|w| w.go(go));
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        self.base.wrapper.regs().itrng_divisor.set(divider - 1);
    }

    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.base.wrapper.regs().generic_input_wires[i].set(wire);
        }
    }

    fn set_mcu_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.base.wrapper.regs().mci_generic_input_wires[i].set(wire);
        }
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }

    fn cycle_count(&mut self) -> u64 {
        self.base.wrapper.regs().cycle_count.get() as u64
    }

    fn save_otp_memory(&self, path: &Path) -> Result<()> {
        let s = crate::vmem::write_otp_vmem_data(self.base.otp_slice())?;
        Ok(std::fs::write(path, s.as_bytes())?)
    }

    fn mcu_manager(&mut self) -> impl McuManager {
        self
    }

    fn caliptra_soc_manager(&mut self) -> impl SocManager {
        self
    }
}

pub struct FpgaRealtimeBus<'a> {
    caliptra_mmio: *mut u32,
    i3c_mmio: *mut u32,
    mci_mmio: *mut u32,
    otp_mmio: *mut u32,
    lc_mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}

impl FpgaRealtimeBus<'_> {
    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        unsafe {
            match addr {
                0x2000_4000..0x2000_5000 => Some(self.i3c_mmio.add((addr - 0x2000_4000) / 4)),
                0x2100_0000..0x21e0_0000 => Some(self.mci_mmio.add((addr - 0x2100_0000) / 4)),
                0x3002_0000..0x3004_0000 => Some(self.caliptra_mmio.add((addr - 0x3000_0000) / 4)),
                0x7000_0000..0x7000_0140 => Some(self.otp_mmio.add((addr - 0x7000_0000) / 4)),
                0x7000_0400..0x7000_048c => Some(self.lc_mmio.add((addr - 0x7000_0400) / 4)),
                _ => {
                    println!("Invalid FPGA address 0x{addr:x}");
                    None
                }
            }
        }
    }
}

impl Bus for FpgaRealtimeBus<'_> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            Ok(unsafe { ptr.read_volatile() })
        } else {
            println!("Error LoadAccessFault");
            Err(BusError::LoadAccessFault)
        }
    }

    fn write(&mut self, _size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            // TODO: support 16-bit and 8-bit writes
            unsafe { ptr.write_volatile(val) };
            Ok(())
        } else {
            Err(BusError::StoreAccessFault)
        }
    }
}

impl McuManager for &mut ModelFpgaRealtime {
    type TMmio<'a>
        = BusMmio<FpgaRealtimeBus<'a>>
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.caliptra_axi_bus())
    }

    const I3C_ADDR: u32 = 0x2000_4000;
    const MCI_ADDR: u32 = 0x2100_0000;
    const TRACE_BUFFER_ADDR: u32 = 0x2101_0000;
    const MBOX_0_ADDR: u32 = 0x2140_0000;
    const MBOX_1_ADDR: u32 = 0x2180_0000;
    const MCU_SRAM_ADDR: u32 = 0x21c0_0000;
    const OTP_CTRL_ADDR: u32 = 0x7000_0000;
    const LC_CTRL_ADDR: u32 = 0x7000_0400;
}

impl SocManager for &mut ModelFpgaRealtime {
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    type TMmio<'a>
        = BusMmio<FpgaRealtimeBus<'a>>
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.caliptra_axi_bus())
    }

    fn delay(&mut self) {
        self.step();
    }
}

impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        self.close_openocd();

        // ensure that we put the I3C target into a state where we will reset it properly
        self.base
            .i3c_core()
            .stdby_ctrl_mode()
            .stby_cr_device_addr()
            .write(|_| StbyCrDeviceAddrWriteVal::from(0));
    }
}

#[cfg(test)]
mod tests {
    use crate::new;

    use super::*;

    #[ignore] // temporarily while we debug the FPGA tests
    #[cfg(feature = "fpga_realtime")]
    #[test]
    fn test_mctp() {
        use caliptra_hw_model::BootParams;

        use crate::DefaultHwModel;

        let binaries = mcu_builder::FirmwareBinaries::from_env().unwrap();
        let mut hw = new(
            InitParams {
                caliptra_rom: &binaries.caliptra_rom,
                mcu_rom: &binaries.mcu_rom,
                vendor_pk_hash: binaries.vendor_pk_hash(),
                active_mode: true,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&binaries.caliptra_fw),
                soc_manifest: Some(&binaries.soc_manifest),
                mcu_fw_image: Some(&binaries.mcu_runtime),
                ..Default::default()
            },
        )
        .unwrap();

        hw.step_until(|m| m.cycle_count() > 300_000_000);

        let send_i3c = |model: &mut DefaultHwModel| {
            println!("Sending I3C MCTP GET_VERSION command");

            let dest_eid = 1;
            let source_eid = 2;
            let mut mctp_packet = vec![
                0x01u8,     // MCTP v1
                dest_eid,   // destination endpoint
                source_eid, // source endpoint
                0xc8,       // start of message, end of message seq num 0, tag 1
            ];

            let mctp_message_header = [
                0x0u8, // message type: 0 (MCTP control), integrity check 0
                0x80,  // request = 1, instance id = 0,
                0x4,   // command: GET_VERSION
                0,     // completion code
            ];
            let mctp_message_body = [
                0xffu8, // MCTP base specification version
            ];
            mctp_packet.extend_from_slice(&mctp_message_header);
            mctp_packet.extend_from_slice(&mctp_message_body);

            model.send_i3c_write(&mctp_packet);
        };

        let recv_i3c = |model: &mut DefaultHwModel, len: u16| -> Vec<u8> {
            println!(
                "Host: checking for I3C MCTP response start, asking for {}",
                len
            );
            let resp = model.recv_i3c(len);

            println!("Host: received I3C MCTP response: {:x?}", resp);
            resp
        };

        send_i3c(&mut hw);
        for _ in 0..10000 {
            hw.step();
        }
        let resp = recv_i3c(&mut hw, 9);
        for _ in 0..10000 {
            hw.step();
        }
        send_i3c(&mut hw);
        for _ in 0..10000 {
            hw.step();
        }
        let resp = recv_i3c(&mut hw, resp[8] as u16 * 4 + 9);
        for _ in 0..10000 {
            hw.step();
        }
        // simple sanity check
        assert_eq!(resp[10], 0xff);
    }
}
