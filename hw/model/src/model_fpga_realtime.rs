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
    SecurityState, XI3CWrapper,
};
use caliptra_registers::i3ccsr::regs::StbyCrDeviceAddrWriteVal;
use mcu_rom_common::{LifecycleControllerState, McuRomBootStatus};
use mcu_testing_common::i3c::{
    I3cBusCommand, I3cBusResponse, I3cTcriCommand, I3cTcriResponseXfer, ResponseDescriptor,
};
use mcu_testing_common::{MCU_RUNNING, MCU_RUNTIME_STARTED};
use registers_generated::i3c::regs::I3c;
use std::io::Write;
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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
    i3c_port: Option<u16>,
    i3c_handle: Option<JoinHandle<()>>,
    i3c_tx: Option<mpsc::Sender<I3cBusResponse>>,
    i3c_next_private_read_len: Option<u32>,
    ibi_sent: bool,
    last_update: u64,
}

impl ModelFpgaRealtime {
    pub fn i3c_target_configured(&mut self) -> bool {
        self.base.i3c_target_configured()
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

    fn print_i3c_registers(&mut self) {
        println!("Dumping registers");
        println!(
            "tti_control: {:08x}",
            u32::from(self.base.i3c_core().tti().control().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_0: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .prot_cap_0()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_1: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .prot_cap_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_2: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .prot_cap_2()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_3: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .prot_cap_3()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_0: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .device_id_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_1: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_2: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_3: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_4: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_5: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_5()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_reserved: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .device_id_reserved()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_0: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .device_status_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_1: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .device_status_1()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_reset: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .device_reset()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_ctrl: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .recovery_ctrl()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_status: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .recovery_status()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_hw_status: {:08x}",
            u32::from(self.base.i3c_core().sec_fw_recovery_if().hw_status().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_0: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .indirect_fifo_ctrl_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_1: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_ctrl_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_0: {:08x}",
            u32::from(
                self.base
                    .i3c_core()
                    .sec_fw_recovery_if()
                    .indirect_fifo_status_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_1: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_2: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_3: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_4: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_reserved: {:08x}",
            self.base
                .i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_reserved()
                .read()
                .swap_bytes()
        );
    }

    fn forward_i3c_to_controller(
        running: Arc<AtomicBool>,
        i3c_rx: mpsc::Receiver<I3cBusCommand>,
        controller: XI3CWrapper,
    ) {
        // check if we need to write any I3C packets to Caliptra
        while running.load(Ordering::Relaxed) {
            for rx in i3c_rx.try_iter() {
                println!("[hw-model-fpga] I3C command received: {:02x?}", rx);
                match rx.cmd.cmd {
                    I3cTcriCommand::Regular(_cmd) => {
                        if rx.cmd.data.len() > 0 {
                            let _ = controller.write(&rx.cmd.data);
                        }
                    }
                    // these aren't used
                    _ => todo!(),
                }
            }
        }
    }

    fn handle_i3c(&mut self) {
        const MCTP_MDB: u8 = 0xae;
        let Some(tx) = self.i3c_tx.as_ref() else {
            return;
        };
        // check if we need to read any I3C packets from Caliptra
        if self.base.i3c_controller().ibi_ready() {
            println!("[hw-model-fpga] I3C IBI received");
            match self.base.i3c_controller().ibi_recv(None) {
                Ok(ibi) => {
                    if ibi.len() < 5 || ibi[0] != MCTP_MDB {
                        println!("Ignoring unexpected I3C IBI received: {:02x?}", ibi);
                        return;
                    }
                    // forward the IBI
                    tx.send(I3cBusResponse {
                        addr: self.i3c_address().unwrap_or_default().into(),
                        ibi: Some(MCTP_MDB),
                        resp: I3cTcriResponseXfer {
                            resp: ResponseDescriptor::default(),
                            data: vec![],
                        },
                    })
                    .expect("Failed to forward I3C IBI response to channel");
                    self.i3c_next_private_read_len =
                        Some(u32::from_be_bytes(ibi[1..5].try_into().unwrap()));
                }
                Err(e) => {
                    println!("Error receiving I3C IBI: {:?}", e);
                }
            }
        }
        // check if we should do attempt a private read
        if let Some(private_read_len) = self.i3c_next_private_read_len.take() {
            println!(
                "[hw-model-fpga] I3C trying private read len {}",
                private_read_len
            );
            match self
                .base
                .i3c_controller()
                //.read(private_read_len.next_multiple_of(4) as u16)
                .read(private_read_len as u16)
            {
                Ok(data) => {
                    let data = data[0..private_read_len as usize].to_vec();
                    // forward the private read
                    let mut resp = ResponseDescriptor::default();
                    resp.set_data_length(data.len() as u16);
                    println!("[hw-model-fpga] Forwarding private read {:02x?}", data);
                    tx.send(I3cBusResponse {
                        addr: self.i3c_address().unwrap_or_default().into(),
                        ibi: None,
                        resp: I3cTcriResponseXfer { resp, data },
                    })
                    .expect("Failed to forward I3C private read response to channel");
                }
                Err(e) => {
                    println!("Error receiving I3C private read: {:?}", e);
                    // retry
                    self.i3c_next_private_read_len = Some(private_read_len);
                }
            }
        }
    }
}

impl McuHwModel for ModelFpgaRealtime {
    fn step(&mut self) {
        self.base.step();
        self.handle_i3c();
        // let now = self.cycle_count();
        // if now > self.last_update + 10_000_000 {
        //     self.last_update = now;
        //     println!(
        //         "{} I3C controller status: {:x}",
        //         now,
        //         self.base
        //             .i3c_controller()
        //             .controller
        //             .lock()
        //             .unwrap()
        //             .status()
        //     );
        // }
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
            LifecycleControllerState::Raw
            | LifecycleControllerState::Prod
            | LifecycleControllerState::ProdEnd => security_state_prod,
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

        let (i3c_rx, i3c_tx) = if let Some(i3c_port) = params.i3c_port {
            println!(
                "Starting I3C socket on port {} and connected to hardware",
                i3c_port
            );
            let (rx, tx) =
                mcu_testing_common::i3c_socket_server::start_i3c_socket(&MCU_RUNNING, i3c_port);

            (Some(rx), Some(tx))
        } else {
            (None, None)
        };

        let i3c_handle = if let Some(i3c_rx) = i3c_rx {
            // start a thread to forward I3C packets from the mpsc receiver to the I3C controller in the FPGA model
            let running = base.realtime_thread_exit_flag.clone();
            let controller = base.i3c_controller();
            let i3c_handle = std::thread::spawn(move || {
                Self::forward_i3c_to_controller(running, i3c_rx, controller);
            });
            Some(i3c_handle)
        } else {
            None
        };

        let m = Self {
            base,

            openocd: None,
            // TODO: start the I3C socket and hook up to the FPGA model
            i3c_port: params.i3c_port,
            i3c_handle,
            i3c_tx,
            i3c_next_private_read_len: None,
            ibi_sent: false,
            last_update: 0,
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

        const BOOT_CYCLES: u64 = 800_000_000;
        self.step_until(|hw| {
            hw.cycle_count() >= BOOT_CYCLES
                || hw.mci_flow_status() == u32::from(McuRomBootStatus::ColdBootFlowComplete)
        });
        println!(
            "Boot completed at cycle count {}, flow status {}",
            self.cycle_count(),
            u32::from(self.mci_flow_status())
        );
        assert_eq!(
            u32::from(McuRomBootStatus::ColdBootFlowComplete),
            self.mci_flow_status()
        );
        MCU_RUNTIME_STARTED.store(true, Ordering::Relaxed);
        // turn off recovery
        self.base.recovery_started = false;
        println!("Resetting I3C controlller");
        {
            let ctrl = self.base.i3c_controller.controller.lock().unwrap();
            ctrl.ready.set(false);
        }
        self.base.i3c_controller.configure();

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

    fn start_i3c_controller(&mut self) {
        //self.base.i3c_controller.configure();
        self.base
            .i3c_controller
            .controller
            .lock()
            .unwrap()
            .interrupt_enable_set(0x80 | 0x8000);
    }

    fn i3c_address(&self) -> Option<u8> {
        Some(self.base.i3c_controller.get_primary_addr())
    }

    fn i3c_port(&self) -> Option<u16> {
        self.i3c_port
    }

    fn mci_flow_status(&mut self) -> u32 {
        self.base.mci_flow_status()
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

        self.base
            .realtime_thread_exit_flag
            .store(false, Ordering::Relaxed);
        if let Some(handle) = self.i3c_handle.take() {
            handle.join().expect("Failed to join I3C thread");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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

    use bitfield::bitfield;
    use caliptra_hw_model::xi3c;
    use caliptra_hw_model::xi3c::Ccc;
    use registers_generated::i3c::bits::HcControl::{BusEnable, ModeSelector};
    use registers_generated::i3c::bits::{
        DeviceStatus0, IndirectFifoStatus0, ProtCap2, ProtCap3, QueueThldCtrl, RecoveryStatus,
        RingHeadersSectionOffset, StbyCrCapabilities, StbyCrControl, StbyCrDeviceAddr,
        StbyCrVirtDeviceAddr, TtiQueueThldCtrl,
    };
    use registers_generated::i3c::regs::I3c;
    use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
    use uio::UioDevice;
    use zerocopy::{FromBytes, IntoBytes};

    // FPGA wrapper register offsets
    const FPGA_WRAPPER_MAGIC_OFFSET: isize = 0x0000 / 4;
    const FPGA_WRAPPER_VERSION_OFFSET: isize = 0x0004 / 4;
    const FPGA_WRAPPER_CONTROL_OFFSET: isize = 0x0008 / 4;
    const FPGA_WRAPPER_STATUS_OFFSET: isize = 0x000C / 4;
    const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x0010 / 4;
    const FPGA_WRAPPER_ITRNG_DIV_OFFSET: isize = 0x0014 / 4;
    const FPGA_WRAPPER_CYCLE_COUNT_OFFSET: isize = 0x0018 / 4;
    const _FPGA_WRAPPER_GENERIC_INPUT_OFFSET: isize = 0x0030 / 4;
    const _FPGA_WRAPPER_GENERIC_OUTPUT_OFFSET: isize = 0x0038 / 4;
    const FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0040 / 4;
    const FPGA_WRAPPER_CSR_HMAC_KEY_OFFSET: isize = 0x0060 / 4;

    const _FPGA_WRAPPER_LSU_USER_OFFSET: isize = 0x0100 / 4;
    const _FPGA_WRAPPER_IFU_USER_OFFSET: isize = 0x0104 / 4;
    const _FPGA_WRAPPER_CLP_USER_OFFSET: isize = 0x0108 / 4;
    const _FPGA_WRAPPER_SOC_CFG_USER_OFFSET: isize = 0x010C / 4;
    const _FPGA_WRAPPER_SRAM_CFG_USER_OFFSET: isize = 0x0110 / 4;
    const FPGA_WRAPPER_MCU_RESET_VECTOR_OFFSET: isize = 0x0114 / 4;
    const _FPGA_WRAPPER_MCI_ERROR: isize = 0x0118 / 4;
    const _FPGA_WRAPPER_MCU_CONFIG: isize = 0x011C / 4;
    const _FPGA_WRAPPER_MCI_GENERIC_INPUT_WIRES_0_OFFSET: isize = 0x0120 / 4;
    const _FPGA_WRAPPER_MCI_GENERIC_INPUT_WIRES_1_OFFSET: isize = 0x0124 / 4;
    const FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_0_OFFSET: isize = 0x0128 / 4;
    const FPGA_WRAPPER_MCI_GENERIC_OUTPUT_WIRES_1_OFFSET: isize = 0x012C / 4;
    const FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
    const FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;
    const FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET: isize = 0x1008 / 4;
    const FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET: isize = 0x100C / 4;

    bitfield! {
        #[derive(Clone, FromBytes, IntoBytes)]
        pub struct RxDescriptor(u32);
        impl Debug;
        pub u16, data_length, set_data_length: 15, 0;
    }

    fn configure_i3c_target(regs: &mut I3c, addr: u8, recovery_enabled: bool) {
        println!("I3C HCI version: {:x}", regs.i3c_base_hci_version.get());

        println!("Set TTI RESET_CONTROL");
        regs.tti_tti_reset_control.set(0x3f);
        println!("TTI RESET_CONTROL: {:x}", regs.tti_tti_reset_control.get());

        // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
        println!("Check ring headers section offset");
        let rhso = regs
            .i3c_base_ring_headers_section_offset
            .read(RingHeadersSectionOffset::SectionOffset);
        if rhso != 0 {
            panic!("RING_HEADERS_SECTION_OFFSET is not 0");
        }

        println!("TTI QUEUE_SIZE: {:x}", regs.tti_tti_queue_size.get());

        // initialize timing registers
        println!("Initialize timing registers");

        // AXI clock is ~200 MHz, I3C clock is 12.5 MHz
        // values of all of these set to 0-5 seem to work for receiving data correctly
        // 6-7 gets corrupted data but will ACK
        // 8+ will fail to ACK
        regs.soc_mgmt_if_t_r_reg.set(0); // rise time of both SDA and SCL in clock units
        regs.soc_mgmt_if_t_f_reg.set(0); // rise time of both SDA and SCL in clock units

        // if this is set to 6+ then ACKs start failing
        regs.soc_mgmt_if_t_hd_dat_reg.set(0); // data hold time in clock units
        regs.soc_mgmt_if_t_su_dat_reg.set(0); // data setup time in clock units

        regs.soc_mgmt_if_t_high_reg.set(0); // High period of the SCL in clock units
        regs.soc_mgmt_if_t_low_reg.set(0); // Low period of the SCL in clock units
        regs.soc_mgmt_if_t_hd_sta_reg.set(0); // Hold time for (repeated) START in clock units
        regs.soc_mgmt_if_t_su_sta_reg.set(0); // Setup time for repeated START in clock units
        regs.soc_mgmt_if_t_su_sto_reg.set(0); // Setup time for STOP in clock units

        // set this to 1 microsecond
        regs.soc_mgmt_if_t_free_reg.set(200); // Bus free time in clock units before doing IBI

        println!(
            "Timing register t_r: {}, t_f: {}, t_hd_dat: {}, t_su_dat: {}, t_high: {}, t_low: {}, t_hd_sta: {}, t_su_sta: {}, t_su_sto: {}, t_free: {}",
            regs.soc_mgmt_if_t_r_reg.get(),
            regs.soc_mgmt_if_t_f_reg.get(),
            regs.soc_mgmt_if_t_hd_dat_reg.get(),
            regs.soc_mgmt_if_t_su_dat_reg.get(),
            regs.soc_mgmt_if_t_high_reg.get(),
            regs.soc_mgmt_if_t_low_reg.get(),
            regs.soc_mgmt_if_t_hd_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sto_reg.get(),
            regs.soc_mgmt_if_t_free_reg.get(),
        );

        // Setup the threshold for the HCI queues (in the internal/private software data structures):
        println!("Setup HCI queue thresholds");
        regs.piocontrol_queue_thld_ctrl.modify(
            QueueThldCtrl::CmdEmptyBufThld.val(0)
                + QueueThldCtrl::RespBufThld.val(1)
                + QueueThldCtrl::IbiStatusThld.val(1),
        );

        println!("Enable the target transaction interface");
        regs.stdby_ctrl_mode_stby_cr_control.modify(
            StbyCrControl::StbyCrEnableInit.val(2) // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable ENTDAA dynamic address assignment
                + StbyCrControl::DaaSetdasaEnable::SET // enable SETDASA dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
        );

        println!(
            "STBY_CR_CONTROL: {:x}",
            regs.stdby_ctrl_mode_stby_cr_control.get()
        );

        // regs.stdby_ctrl_mode_stby_cr_capabilities
        //     .write(StbyCrCapabilities::TargetXactSupport::SET);
        println!(
            "STBY_CR_CAPABILITIES: {:x}",
            regs.stdby_ctrl_mode_stby_cr_capabilities.get()
        );
        if !regs
            .stdby_ctrl_mode_stby_cr_capabilities
            .is_set(StbyCrCapabilities::TargetXactSupport)
        {
            panic!("I3C target transaction support is not enabled");
        }

        // program a static address
        println!("Setting static address to {:x}", addr);
        regs.stdby_ctrl_mode_stby_cr_device_addr.write(
            StbyCrDeviceAddr::StaticAddrValid::SET + StbyCrDeviceAddr::StaticAddr.val(addr as u32),
        );
        if recovery_enabled {
            println!("Setting virtual device static address to {:x}", addr + 1);
            regs.stdby_ctrl_mode_stby_cr_virt_device_addr.write(
                StbyCrVirtDeviceAddr::VirtStaticAddrValid::SET
                    + StbyCrVirtDeviceAddr::VirtStaticAddr.val((addr + 1) as u32),
            );
        }

        println!("Set TTI queue thresholds");
        // set TTI queue thresholds
        regs.tti_tti_queue_thld_ctrl.modify(
            TtiQueueThldCtrl::IbiThld.val(1)
                + TtiQueueThldCtrl::RxDescThld.val(1)
                + TtiQueueThldCtrl::TxDescThld.val(1),
        );
        println!(
            "TTI queue thresholds: {:x}",
            regs.tti_tti_queue_thld_ctrl.get()
        );

        println!(
            "TTI data buffer thresholds ctrl: {:x}",
            regs.tti_tti_data_buffer_thld_ctrl.get()
        );

        println!("Enable PHY to the bus");
        // enable the PHY connection to the bus
        regs.i3c_base_hc_control
            .modify(ModeSelector::SET + BusEnable::CLEAR); // clear is enabled, set is suspended

        println!("Enabling interrupts");
        // regs.tti_interrupt_enable.modify(
        //     InterruptEnable::IbiThldStatEn::SET
        //         + InterruptEnable::RxDescThldStatEn::SET
        //         + InterruptEnable::TxDescThldStatEn::SET
        //         + InterruptEnable::RxDataThldStatEn::SET
        //         + InterruptEnable::TxDataThldStatEn::SET,
        // );
        regs.tti_interrupt_enable.set(0xffff_ffff);
        println!(
            "I3C target interrupt enable {:x}",
            regs.tti_interrupt_enable.get()
        );

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            regs.tti_status.get(),
            regs.tti_interrupt_status.get()
        );

        if recovery_enabled {
            println!("Enabling recovery interface");
            regs.sec_fw_recovery_if_prot_cap_2.write(
                ProtCap2::RecProtVersion.val(0x101)
                    + ProtCap2::AgentCaps.val(
                        (1 << 0) | // device id
                (1 << 4) | // device status
                (1 << 5) | // indirect ctrl
                (1 << 7), // push c-image support
                    ),
            );
            regs.sec_fw_recovery_if_prot_cap_3.write(
                ProtCap3::NumOfCmsRegions.val(1) + ProtCap3::MaxRespTime.val(20), // 1.048576 second maximum response time
            );
            regs.sec_fw_recovery_if_device_status_0
                .write(DeviceStatus0::DevStatus.val(0x3)); // ready to accept recovery image
        }

        println!(
            "I3C recovery prot_cap 2 and 3: {:08x} {:08x}",
            regs.sec_fw_recovery_if_prot_cap_2.get(),
            regs.sec_fw_recovery_if_prot_cap_3.get(),
        );
        println!(
            "I3C recovery device status: {:x}",
            regs.sec_fw_recovery_if_device_status_0
                .read(DeviceStatus0::DevStatus)
        );
    }

    fn print_i3c_register(i3c: &I3c) {
        println!("Dumping registers");
        println!("tti_control {:08x}", i3c.tti_control.get().swap_bytes());
        println!(
            "sec_fw_recovery_if_prot_cap_0: {:08x}",
            i3c.sec_fw_recovery_if_prot_cap_0.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_1: {:08x}",
            i3c.sec_fw_recovery_if_prot_cap_1.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_2: {:08x}",
            i3c.sec_fw_recovery_if_prot_cap_2.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_3: {:08x}",
            i3c.sec_fw_recovery_if_prot_cap_3.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_0: {:08x}",
            i3c.sec_fw_recovery_if_device_id_0.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_1: {:08x}",
            i3c.sec_fw_recovery_if_device_id_1.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_2: {:08x}",
            i3c.sec_fw_recovery_if_device_id_2.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_3: {:08x}",
            i3c.sec_fw_recovery_if_device_id_3.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_4: {:08x}",
            i3c.sec_fw_recovery_if_device_id_4.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_5: {:08x}",
            i3c.sec_fw_recovery_if_device_id_5.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_reserved: {:08x}",
            i3c.sec_fw_recovery_if_device_id_reserved.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_0: {:08x}",
            i3c.sec_fw_recovery_if_device_status_0.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_1: {:08x}",
            i3c.sec_fw_recovery_if_device_status_1.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_reset: {:08x}",
            i3c.sec_fw_recovery_if_device_reset.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_ctrl: {:08x}",
            i3c.sec_fw_recovery_if_recovery_ctrl.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_status: {:08x}",
            i3c.sec_fw_recovery_if_recovery_status.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_hw_status: {:08x}",
            i3c.sec_fw_recovery_if_hw_status.get().swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_0: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_ctrl_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_1: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_ctrl_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_0: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_status_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_1: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_status_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_2: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_status_2
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_3: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_status_3
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_4: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_status_4
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_reserved: {:08x}",
            i3c.sec_fw_recovery_if_indirect_fifo_reserved
                .get()
                .swap_bytes()
        );
    }

    fn empty_rx_queue(i3c: &I3c) {
        while i3c.tti_interrupt_status.get() & 0x801 != 0 {
            let packet = read_packet(i3c);
            println!("Emptying I3C RX queue: {:x?}", packet);
        }
    }

    fn read_packet(i3c: &I3c) -> Vec<u8> {
        assert!(
            i3c.tti_interrupt_status.get() & 0x801 != 0,
            "Expected I3C target to have an RX descriptor waiting"
        );
        let desc0 = RxDescriptor(i3c.tti_rx_desc_queue_port.get());
        println!("Read a descriptor: {:08x}", desc0.0,);
        let mut len = desc0.data_length() as usize;
        let mut data = vec![];
        while len > 0 {
            let dword = i3c.tti_rx_data_port.get();
            let slice = dword.to_le_bytes();
            let valid = len.min(4);
            data.extend(&slice[0..valid]);
            len -= valid;
        }
        data
    }

    fn send_packet(i3c: &I3c, mut data: &[u8]) {
        let mut desc = RxDescriptor(0);
        desc.set_data_length(data.len() as u16);
        i3c.tti_tx_desc_queue_port.set(desc.0);
        while data.len() > 0 {
            let next = &data[..4.min(data.len())];
            let mut word = [0, 0, 0, 0];
            word[..next.len()].copy_from_slice(next);
            let word = u32::from_le_bytes(word);
            i3c.tti_tx_data_port.set(word);
            data = &data[next.len()..];
        }
    }

    #[test]
    fn test_xi3c_ibi_private_read() {
        const AXI_CLOCK_HZ: u32 = 199_999_000;
        const I3C_CLOCK_HZ: u32 = 12_500_000;
        let dev0 = UioDevice::blocking_new(0).unwrap();
        let dev1 = UioDevice::blocking_new(1).unwrap();
        let wrapper = dev0.map_mapping(0).unwrap() as *mut u32;
        let i3c_target_raw = dev1.map_mapping(2).unwrap();
        let i3c_target: &mut I3c = unsafe { &mut *(i3c_target_raw as *mut I3c) };
        const I3C_TARGET_ADDR: u8 = 0x5a;
        let use_dynamic_addr = true;

        let fpga_version =
            unsafe { core::ptr::read_volatile(wrapper.offset(FPGA_WRAPPER_VERSION_OFFSET)) };
        println!("FPGA version: {:08x}", fpga_version);

        println!("Bring SS out of reset");
        unsafe {
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0);
            core::ptr::write_volatile(wrapper.offset(FPGA_WRAPPER_CONTROL_OFFSET), 0x3);
        }
        println!("Configuring I3C target");
        configure_i3c_target(i3c_target, I3C_TARGET_ADDR, true);

        let xi3c_controller_ptr = dev0.map_mapping(3).unwrap() as *mut u32;
        let xi3c: &xi3c::XI3c = unsafe { &*(xi3c_controller_ptr as *const xi3c::XI3c) };
        println!("XI3C HW version = {:x}", xi3c.version.get());

        let mut i3c_controller = xi3c::Controller::new(xi3c::Config {
            device_id: 0,
            base_address: xi3c_controller_ptr,
            input_clock_hz: AXI_CLOCK_HZ,
            rw_fifo_depth: 16,
            wr_threshold: 12 * 4,
            device_count: 1,
            ibi_capable: true,
            hj_capable: false,
            entdaa_enable: true,
            known_static_addrs: vec![I3C_TARGET_ADDR, I3C_TARGET_ADDR + 1],
        });

        i3c_controller.set_s_clk(AXI_CLOCK_HZ, I3C_CLOCK_HZ, 1);
        i3c_controller.cfg_initialize().unwrap();
        // println!("I3C controller timing registers:");
        // println!(
        //     "  od scl high: {}",
        //     i3c_controller.regs().od_scl_high_time.get()
        // );
        // println!(
        //     "  od scl low: {}",
        //     i3c_controller.regs().od_scl_low_time.get()
        // );
        // println!("  scl high: {}", i3c_controller.regs().scl_high_time.get());
        // println!("  scl low: {}", i3c_controller.regs().scl_low_time.get());
        // println!("  sda hold: {}", i3c_controller.regs().sda_hold_time.get());
        // println!("  tsu start: {}", i3c_controller.regs().tsu_start.get());
        // println!("  tsu stop: {}", i3c_controller.regs().tsu_stop.get());
        // println!("  bus free time: {}", i3c_controller.regs().bus_idle.get());
        // println!("  thld start: {}", i3c_controller.regs().thd_start.get());

        // check I3C target address
        let mut target_addr = I3C_TARGET_ADDR;
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::DynamicAddrValid)
            == 1
        {
            let addr = i3c_target
                .stdby_ctrl_mode_stby_cr_device_addr
                .read(StbyCrDeviceAddr::DynamicAddr);
            println!("I3C target dynamic address: {:x}", addr,);
            if use_dynamic_addr {
                target_addr = addr as u8;
            }
        }
        if i3c_target
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::StaticAddrValid)
            == 1
        {
            println!(
                "I3C target static address: {:x}",
                i3c_target
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::StaticAddr) as u8,
            );
        }
        println!("Using {:x} as target address", target_addr);

        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            ..Default::default()
        };
        if !use_dynamic_addr {
            const XI3C_CCC_BRDCAST_SETAASA: u8 = 0x29;
            println!("Broadcast CCC SETAASA");
            let result =
                i3c_controller.send_transfer_cmd(&mut cmd, Ccc::Byte(XI3C_CCC_BRDCAST_SETAASA));
            assert!(result.is_ok(), "Failed to ack broadcast CCC SETAASA");
            println!("Acknowledge received");
        }

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );

        // Fill data to buffer
        let mut tx_data = [0u8; 50];
        for i in 0..50 as usize {
            tx_data[i] = i as u8; // Test data
        }

        // println!(
        //     "I3C fifo level status 1: {:x}",
        //     i3c_controller.regs().fifo_lvl_status_1.get()
        // );
        // while i3c_controller.regs().fifo_lvl_status_1.get() >> 16 > 0 {
        //     println!(
        //         "I3C controller has response fifo: {:x}",
        //         i3c_controller.regs().resp_status_fifo.get()
        //     );
        // }

        print_i3c_register(i3c_target);

        // let's send a message back
        println!("Writing data back to controller: {:x?}", tx_data);
        send_packet(i3c_target, &tx_data);

        println!("I3C controller status: {:x}", i3c_controller.status());
        println!("Starting IBI 0xae with 0 bytes");

        // trigger an IBI with value 0xae (MCTP pending read)
        i3c_target.tti_tti_ibi_port.set(0xae00_0000);
        // i3c_target.tti_tti_ibi_port.set(0x01234_5678);
        // i3c_target.tti_tti_ibi_port.set(0x9abc_defe);

        std::thread::sleep(Duration::from_millis(1));

        println!(
            "I3C target status {:x}, interrupt enable {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_enable.get(),
            i3c_target.tti_interrupt_status.get()
        );

        println!("I3C controller status: {:x}", i3c_controller.status());

        // println!(
        //     "I3C controller IBI target address: 0x{:x}",
        //     i3c_controller.regs().target_addr_bcr.get()
        // );

        // if i3c_controller.status() & 0x80 != 0 {
        //     println!(
        //         "I3C fifo level status 1: {:x}",
        //         i3c_controller.regs().fifo_lvl_status_1.get()
        //     );
        //     println!(
        //         "I3C controller has response fifo: {:x}",
        //         i3c_controller.regs().resp_status_fifo.get()
        //     );
        // }
        println!("I3C controller status: {:x}", i3c_controller.status());

        let ibi_data = i3c_controller
            .ibi_recv_polled(Duration::from_secs(1))
            .expect("Should have received an IBI");
        println!("Got IBI data {:x?}", ibi_data);
        println!("I3C controller status: {:x}", i3c_controller.status());

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );

        // now do the private read
        println!("Sending a read request to the target");
        cmd.target_addr = target_addr;
        cmd.no_repeated_start = 1;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;
        let recv = i3c_controller
            .master_recv_polled(None, &mut cmd, 50)
            .expect("Failed to start receive from target");

        println!("Received data from target: {:x?}", recv);
        assert_eq!(recv, tx_data);

        println!(
            "I3C target status {:x}, interrupt status {:x}",
            i3c_target.tti_status.get(),
            i3c_target.tti_interrupt_status.get()
        );
    }
}
