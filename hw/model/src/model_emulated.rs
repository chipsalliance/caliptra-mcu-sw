// Licensed under the Apache-2.0 license

use crate::bus_logger::BusLogger;
use crate::bus_logger::LogFile;
use crate::otp_provision::lc_generate_memory;
use crate::otp_provision::otp_generate_lifecycle_tokens_mem;
use crate::trace_path_or_env;
use crate::InitParams;
use crate::McuHwModel;
use crate::McuManager;
use crate::DEFAULT_LIFECYCLE_RAW_TOKENS;
use anyhow::Result;
use caliptra_api::SocManager;
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusError;
use caliptra_emu_bus::BusMmio;
use caliptra_emu_bus::{Clock, Event};
use caliptra_emu_cpu::{Cpu, CpuArgs, InstrTracer, Pic};
use caliptra_emu_periph::SocToCaliptraBus;
use caliptra_emu_periph::{
    ActionCb, CaliptraRootBus, CaliptraRootBusArgs, MailboxRequester, ReadyForFwCb, TbServicesCb,
};
use caliptra_emu_types::RvAddr;
use caliptra_emu_types::RvData;
use caliptra_emu_types::RvSize;
use caliptra_hw_model::DeviceLifecycle;
use caliptra_hw_model::ModelError;
use caliptra_hw_model::Output;
use caliptra_hw_model::SecurityState;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;
use emulator_periph::McuRootBusOffsets;
use emulator_periph::{
    I3c, I3cController, Mci, McuMailbox0Internal, McuRootBus, McuRootBusArgs, Otp, OtpArgs,
};
use emulator_registers_generated::root_bus::AutoRootBus;
use mcu_config::McuMemoryMap;
use mcu_rom_common::LifecycleControllerState;
use mcu_rom_common::McuRomBootStatus;
use registers_generated::fuses;
use semver::Version;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

const DEFAULT_AXI_PAUSER: u32 = 0xaaaa_aaaa;

/// Emulated model
pub struct ModelEmulated {
    cpu: Cpu<BusLogger<AutoRootBus>>,
    soc_to_caliptra_bus: SocToCaliptraBus,
    output: Output,
    caliptra_trace_fn: Option<Box<InstrTracer<'static>>>,
    ready_for_fw: Rc<Cell<bool>>,
    cpu_enabled: Rc<Cell<bool>>,
    trace_path: Option<PathBuf>,

    // Keep this even when not including the coverage feature to keep the
    // interface consistent
    _rom_image_tag: u64,
    iccm_image_tag: Option<u64>,

    events_to_caliptra: mpsc::Sender<Event>,
    events_from_caliptra: mpsc::Receiver<Event>,
    collected_events_from_caliptra: Vec<Event>,
}

fn hash_slice(slice: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::hash::Hash::hash_slice(slice, &mut hasher);
    hasher.finish()
}

impl McuHwModel for ModelEmulated {
    fn new_unbooted(params: InitParams) -> Result<Self>
    where
        Self: Sized,
    {
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let timer = clock.timer();

        let ready_for_fw = Rc::new(Cell::new(false));
        let ready_for_fw_clone = ready_for_fw.clone();

        let cpu_enabled = Rc::new(Cell::new(false));
        let cpu_enabled_cloned = cpu_enabled.clone();

        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

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

        let bus_args = CaliptraRootBusArgs {
            rom: params.caliptra_rom.into(),
            tb_services_cb: TbServicesCb::new(move |ch| {
                output_sink.set_now(timer.now());
                output_sink.push_uart_char(ch);
            }),
            ready_for_fw_cb: ReadyForFwCb::new(move |_| {
                ready_for_fw_clone.set(true);
            }),
            bootfsm_go_cb: ActionCb::new(move || {
                cpu_enabled_cloned.set(true);
            }),
            security_state,
            dbg_manuf_service_req: params.dbg_manuf_service,
            subsystem_mode: params.active_mode,
            prod_dbg_unlock_keypairs: params.prod_dbg_unlock_keypairs,
            debug_intent: params.debug_intent,
            cptra_obf_key: params.cptra_obf_key,

            itrng_nibbles: Some(params.itrng_nibbles),
            etrng_responses: params.etrng_responses,
            clock: clock.clone(),
            ..CaliptraRootBusArgs::default()
        };
        let mut root_bus = CaliptraRootBus::new(bus_args);

        root_bus
            .soc_reg
            .set_hw_config((1 | if params.active_mode { 1 << 5 } else { 0 }).into());

        {
            let mut iccm_ram = root_bus.iccm.ram().borrow_mut();
            let Some(iccm_dest) = iccm_ram.data_mut().get_mut(0..params.caliptra_iccm.len()) else {
                return Err(ModelError::ProvidedIccmTooLarge.into());
            };
            iccm_dest.copy_from_slice(params.caliptra_iccm);

            let Some(dccm_dest) = root_bus
                .dccm
                .data_mut()
                .get_mut(0..params.caliptra_dccm.len())
            else {
                return Err(ModelError::ProvidedDccmTooLarge.into());
            };
            dccm_dest.copy_from_slice(params.caliptra_dccm);
        }

        root_bus
            .soc_reg
            .set_hw_config((1 | if params.active_mode { 1 << 5 } else { 0 }).into());

        let soc_to_caliptra_bus =
            root_bus.soc_to_caliptra_bus(MailboxRequester::SocUser(DEFAULT_AXI_PAUSER));

        let mut hasher = DefaultHasher::new();
        std::hash::Hash::hash_slice(params.caliptra_rom, &mut hasher);
        let image_tag = hasher.finish();

        let memory_map = McuMemoryMap::default();
        let offsets = McuRootBusOffsets {
            rom_offset: memory_map.rom_offset,
            ram_offset: memory_map.sram_offset,
            ram_size: memory_map.sram_size,
            ..Default::default()
        };

        let bus_args = McuRootBusArgs {
            rom: params.mcu_rom.into(),
            pic: pic.clone(),
            clock: clock.clone(),
            offsets,
            ..Default::default()
        };
        let mcu_root_bus = McuRootBus::new(bus_args).unwrap();
        let mut i3c_controller = I3cController::default();
        let i3c_irq = pic.register_irq(McuRootBus::I3C_IRQ);
        let i3c = I3c::new(
            &clock.clone(),
            &mut i3c_controller,
            i3c_irq,
            Version::new(2, 0, 0),
        );
        let mut otp_mem = vec![0u8; fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE];
        if let Some(state) = params.lifecycle_controller_state {
            println!("Setting lifecycle controller state to {}", state);
            let mem = lc_generate_memory(state, 1)?;
            otp_mem[fuses::LIFE_CYCLE_BYTE_OFFSET..fuses::LIFE_CYCLE_BYTE_OFFSET + mem.len()]
                .copy_from_slice(&mem);

            let tokens = params
                .lifecycle_tokens
                .as_ref()
                .unwrap_or(&DEFAULT_LIFECYCLE_RAW_TOKENS);

            let mem = otp_generate_lifecycle_tokens_mem(tokens)?;
            otp_mem[fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET
                ..fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET
                    + fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_SIZE]
                .copy_from_slice(&mem);
        }

        let otp = Otp::new(
            &clock.clone(),
            OtpArgs {
                raw_memory: Some(otp_mem),
                vendor_pk_hash: params.vendor_pk_hash,
                vendor_pqc_type: params
                    .vendor_pqc_type
                    .unwrap_or(FwVerificationPqcKeyType::LMS),
                ..Default::default()
            },
        )?;
        let ext_mci = root_bus.mci_external_regs();
        let mci_irq = pic.register_irq(McuRootBus::MCI_IRQ);
        let mci = Mci::new(
            &clock.clone(),
            ext_mci,
            Rc::new(RefCell::new(mci_irq)),
            Some(McuMailbox0Internal::new(&clock.clone())),
        );

        let delegates: Vec<Box<dyn caliptra_emu_bus::Bus>> =
            vec![Box::new(mcu_root_bus), Box::new(soc_to_caliptra_bus)];

        let auto_root_bus = AutoRootBus::new(
            delegates,
            None,
            Some(Box::new(i3c)),
            None,
            None,
            Some(Box::new(mci)),
            None,
            None,
            None,
            Some(Box::new(otp)),
            None,
            None,
            None,
            None,
        );

        let args = CpuArgs::default();
        let mut cpu = Cpu::new(BusLogger::new(auto_root_bus), clock, pic, args);
        cpu.write_pc(McuMemoryMap::default().rom_offset);

        if let Some(stack_info) = params.stack_info {
            cpu.with_stack_info(stack_info);
        }

        let (events_to_caliptra, events_from_caliptra) = cpu.register_events();
        let soc_to_caliptra_bus =
            root_bus.soc_to_caliptra_bus(MailboxRequester::SocUser(DEFAULT_AXI_PAUSER));

        let mut m = ModelEmulated {
            soc_to_caliptra_bus,
            output,
            cpu,
            caliptra_trace_fn: None,
            ready_for_fw,
            cpu_enabled,
            trace_path: trace_path_or_env(params.trace_path),
            _rom_image_tag: image_tag,
            iccm_image_tag: None,
            events_to_caliptra,
            events_from_caliptra,
            collected_events_from_caliptra: vec![],
        };
        // Turn tracing on if the trace path was set
        m.tracing_hint(true);

        Ok(m)
    }

    fn boot(&mut self, _boot_params: crate::BootParams) -> Result<()>
    where
        Self: Sized,
    {
        self.cpu_enabled.set(true);
        for _ in 0..10_000 {
            self.step();
        }
        use std::io::Write;
        let mut w = std::io::Sink::default();
        if !self.output().peek().is_empty() {
            w.write_all(self.output().take(usize::MAX).as_bytes())
                .unwrap();
        }
        assert_eq!(
            u32::from(McuRomBootStatus::CaliptraBootGoAsserted),
            self.mci_flow_status()
        );
        // TODO: load caliptra and MCU firmware
        Ok(())
    }

    fn type_name(&self) -> &'static str {
        "ModelEmulated"
    }

    fn ready_for_fw(&self) -> bool {
        self.ready_for_fw.get()
    }

    fn step(&mut self) {
        if self.cpu_enabled.get() {
            self.cpu.step(self.caliptra_trace_fn.as_deref_mut());
        }
        let events = self.events_from_caliptra.try_iter().collect::<Vec<_>>();
        self.collected_events_from_caliptra.extend(events);
    }

    fn output(&mut self) -> &mut Output {
        // In case the caller wants to log something, make sure the log has the
        // correct time.env::
        self.output.sink().set_now(self.cpu.clock.now());
        &mut self.output
    }

    fn cover_fw_image(&mut self, fw_image: &[u8]) {
        let iccm_image = &fw_image[IMAGE_MANIFEST_BYTE_SIZE..];
        self.iccm_image_tag = Some(hash_slice(iccm_image));
    }

    fn tracing_hint(&mut self, enable: bool) {
        if enable == self.caliptra_trace_fn.is_some() {
            // No change
            return;
        }
        self.caliptra_trace_fn = None;
        self.cpu.bus.log = None;
        let Some(trace_path) = &self.trace_path else {
            return;
        };

        let mut log = match LogFile::open(trace_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Unable to open file {trace_path:?}: {e}");
                return;
            }
        };
        self.cpu.bus.log = Some(log.clone());
        self.caliptra_trace_fn = Some(Box::new(move |pc, _instr| {
            writeln!(log, "pc=0x{pc:x}").unwrap();
        }))
    }

    fn set_axi_user(&mut self, _axi_user: u32) {
        unimplemented!();
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        self.collected_events_from_caliptra.drain(..).collect()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        self.events_to_caliptra.clone()
    }

    fn cycle_count(&mut self) -> u64 {
        self.cpu.clock.now()
    }

    fn save_otp_memory(&self, _path: &Path) -> Result<()> {
        unimplemented!()
    }

    fn mci_flow_status(&mut self) -> u32 {
        self.cpu
            .bus
            .bus
            .mci_periph
            .as_mut()
            .unwrap()
            .periph
            .read_mci_reg_fw_flow_status()
    }

    fn mcu_manager(&mut self) -> impl McuManager {
        self
    }

    fn caliptra_soc_manager(&mut self) -> impl caliptra_api::SocManager {
        self
    }
}

impl ModelEmulated {
    fn caliptra_axi_bus(&mut self) -> EmulatedAxiBus<'_> {
        EmulatedAxiBus { model: self }
    }
}

pub struct EmulatedAxiBus<'a> {
    model: &'a mut ModelEmulated,
}

impl Bus for EmulatedAxiBus<'_> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        let bus: &mut dyn Bus = match addr {
            0x3002_0000..=0x3003_ffff => &mut self.model.soc_to_caliptra_bus,
            _ => &mut self.model.cpu.bus,
        };
        let result = bus.read(size, addr);
        self.model.cpu.bus.log_read("SoC", size, addr, result);
        result
    }
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        let bus: &mut dyn Bus = match addr {
            0x3002_0000..=0x3003_ffff => &mut self.model.soc_to_caliptra_bus,
            _ => &mut self.model.cpu.bus,
        };
        let result = bus.write(size, addr, val);
        self.model.cpu.bus.log_write("SoC", size, addr, val, result);
        result
    }
}

impl McuManager for &mut ModelEmulated {
    type TMmio<'a>
        = BusMmio<EmulatedAxiBus<'a>>
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

impl SocManager for &mut ModelEmulated {
    type TMmio<'a>
        = BusMmio<EmulatedAxiBus<'a>>
    where
        Self: 'a;

    fn delay(&mut self) {
        self.step();
    }

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.caliptra_axi_bus())
    }

    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;
}

#[cfg(test)]
mod test {
    use mcu_rom_common::McuRomBootStatus;

    use crate::{InitParams, McuHwModel, ModelEmulated};

    #[test]
    fn test_new_unbooted() {
        let mcu_rom = mcu_builder::rom_build(None, "").expect("Could not build MCU ROM");
        let mcu_runtime = &mcu_builder::runtime_build_with_apps_cached(
            &[],
            None,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .expect("Could not build MCU runtime");
        let mut caliptra_builder = mcu_builder::CaliptraBuilder::new(
            false,
            None,
            None,
            None,
            None,
            Some(mcu_rom.clone().into()),
            None,
            None,
            None,
        );
        let caliptra_rom = caliptra_builder
            .get_caliptra_rom()
            .expect("Could not build Caliptra ROM");
        let caliptra_fw = caliptra_builder
            .get_caliptra_fw()
            .expect("Could not build Caliptra FW bundle");
        let vendor_pk_hash = caliptra_builder
            .get_vendor_pk_hash()
            .expect("Could not get vendor PK hash");
        println!("Vendor PK hash: {:x?}", vendor_pk_hash);
        let vendor_pk_hash = hex::decode(vendor_pk_hash).unwrap().try_into().unwrap();
        let soc_manifest = caliptra_builder.get_soc_manifest().unwrap();

        let mcu_rom = std::fs::read(mcu_rom).unwrap();
        let mcu_runtime = std::fs::read(mcu_runtime).unwrap();
        let soc_manifest = std::fs::read(soc_manifest).unwrap();
        let caliptra_rom = std::fs::read(caliptra_rom).unwrap();
        let caliptra_fw = std::fs::read(caliptra_fw).unwrap();

        let mut model = ModelEmulated::new_unbooted(InitParams {
            mcu_rom: &mcu_rom,
            mcu_firmware: &mcu_runtime,
            soc_manifest: &soc_manifest,
            caliptra_rom: &caliptra_rom,
            caliptra_firmware: &caliptra_fw,
            vendor_pk_hash: Some(vendor_pk_hash),
            ..Default::default()
        })
        .unwrap();
        model.cpu_enabled.set(true);
        for _ in 0..10_000 {
            model.step();
        }
        use std::io::Write;
        let mut w = std::io::Sink::default();
        if !model.output().peek().is_empty() {
            w.write_all(model.output().take(usize::MAX).as_bytes())
                .unwrap();
        }
        assert_eq!(
            u32::from(McuRomBootStatus::CaliptraBootGoAsserted),
            model.mci_flow_status()
        );
    }
}
