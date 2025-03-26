// Licensed under the Apache-2.0 license

use crate::bus_logger::BusLogger;
use crate::bus_logger::LogFile;
use crate::bus_logger_mcu::McuBusLogger;
use crate::trace_path_or_env;
use crate::InitParams;
use crate::McuHwModel;
use crate::ModelError;
use crate::Output;
use crate::TrngMode;
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Event;
use caliptra_emu_bus::{Bus, BusMmio};
use caliptra_emu_cpu::{Cpu as CaliptraCpu, InstrTracer as CaliptraInstrTracer};
use caliptra_emu_periph::ActionCb;
use caliptra_emu_periph::ReadyForFwCb;
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, SocToCaliptraBus, TbServicesCb};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;
use emulator_bus::BusConverter;
use emulator_bus::Clock as McuClock;
use emulator_cpu::{Cpu as McuCpu, InstrTracer as McuInstrTracer, Pic};
use emulator_periph::{
    CaliptraRootBus as McuRootBus, CaliptraRootBusArgs as McuRootBusArgs, I3c, I3cController, Mci,
    Otp,
};
use emulator_registers_generated::root_bus::AutoRootBus;
use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::Hasher;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

use caliptra_api::soc_mgr::SocManager;
pub struct EmulatedApbBus<'a> {
    model: &'a mut ModelEmulated,
}

impl<'a> Bus for EmulatedApbBus<'a> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.read(size, addr);
        self.model
            .caliptra_cpu
            .bus
            .log_read("SoC", size, addr, result);
        result
    }
    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.write(size, addr, val);
        self.model
            .caliptra_cpu
            .bus
            .log_write("SoC", size, addr, val, result);
        result
    }
}

/// Emulated model
pub struct ModelEmulated {
    caliptra_cpu: CaliptraCpu<BusLogger<CaliptraRootBus>>,
    mcu_cpu: McuCpu<McuBusLogger<AutoRootBus>>,
    soc_to_caliptra_bus: SocToCaliptraBus,
    output: Output,
    caliptra_trace_fn: Option<Box<CaliptraInstrTracer<'static>>>,
    mcu_trace_fn: Option<Box<McuInstrTracer<'static>>>,
    ready_for_fw: Rc<Cell<bool>>,
    cpu_enabled: Rc<Cell<bool>>,
    trace_path: Option<PathBuf>,

    // Keep this even when not including the coverage feature to keep the
    // interface consistent
    _rom_image_tag: u64,
    iccm_image_tag: Option<u64>,
    trng_mode: TrngMode,

    events_to_caliptra: mpsc::Sender<Event>,
    events_from_caliptra: mpsc::Receiver<Event>,
    collected_events_from_caliptra: Vec<Event>,
}

fn hash_slice(slice: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::hash::Hash::hash_slice(slice, &mut hasher);
    hasher.finish()
}

impl SocManager for ModelEmulated {
    type TMmio<'a> = BusMmio<EmulatedApbBus<'a>>;

    fn delay(&mut self) {
        self.step();
    }

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.apb_bus())
    }

    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_SHA512_ACC_ADDR: u32 = 0x3002_1000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;
}

impl McuHwModel for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let clock = Clock::new();
        let timer = clock.timer();

        let ready_for_fw = Rc::new(Cell::new(false));
        let ready_for_fw_clone = ready_for_fw.clone();

        let cpu_enabled = Rc::new(Cell::new(false));
        let cpu_enabled_cloned = cpu_enabled.clone();

        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

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
            security_state: params.security_state,
            dbg_manuf_service_req: params.dbg_manuf_service,
            active_mode: params.active_mode,
            prod_dbg_unlock_keypairs: params.prod_dbg_unlock_keypairs,
            debug_intent: params.debug_intent,
            cptra_obf_key: params.cptra_obf_key,

            itrng_nibbles: Some(params.itrng_nibbles),
            etrng_responses: params.etrng_responses,
            ..CaliptraRootBusArgs::default()
        };
        let mut root_bus = CaliptraRootBus::new(&clock, bus_args);

        let trng_mode = TrngMode::resolve(params.trng_mode);
        root_bus.soc_reg.set_hw_config(
            (match trng_mode {
                TrngMode::Internal => 1,
                TrngMode::External => 0,
            } | if params.active_mode { 1 << 5 } else { 0 })
            .into(),
        );

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
        let soc_to_caliptra_bus = root_bus.soc_to_caliptra_bus();
        let soc_to_caliptra_bus2 = root_bus.soc_to_caliptra_bus();
        let (events_to_caliptra, events_from_caliptra, caliptra_cpu) = {
            let mut cpu = CaliptraCpu::new(BusLogger::new(root_bus), clock);
            if let Some(stack_info) = params.stack_info {
                cpu.with_stack_info(stack_info);
            }
            let (events_to_caliptra, events_from_caliptra) = cpu.register_events();
            (events_to_caliptra, events_from_caliptra, cpu)
        };

        let mut hasher = DefaultHasher::new();
        std::hash::Hash::hash_slice(params.caliptra_rom, &mut hasher);
        let image_tag = hasher.finish();

        // this just immediately exits
        let _mcu_firmware = [0xb7, 0xf6, 0x00, 0x20, 0x94, 0xc2];

        let clock = Rc::new(McuClock::new());
        let pic = Rc::new(Pic::new());
        let bus_args = McuRootBusArgs {
            rom: params.mcu_rom.into(),
            pic: pic.clone(),
            clock: clock.clone(),
            ..Default::default()
        };
        let mcu_root_bus = McuRootBus::new(bus_args).unwrap();
        let mut i3c_controller = I3cController::default();
        let i3c_error_irq = pic.register_irq(McuRootBus::I3C_ERROR_IRQ);
        let i3c_notif_irq = pic.register_irq(McuRootBus::I3C_NOTIF_IRQ);
        let i3c = I3c::new(
            &clock.clone(),
            &mut i3c_controller,
            i3c_error_irq,
            i3c_notif_irq,
        );
        let otp = Otp::new(&clock.clone(), None, None, None)?;
        let mci = Mci::default();

        let delegates: Vec<Box<dyn emulator_bus::Bus>> = vec![
            Box::new(mcu_root_bus),
            Box::new(BusConverter::new(Box::new(soc_to_caliptra_bus2))),
        ];

        let auto_root_bus = AutoRootBus::new(
            delegates,
            Some(Box::new(i3c)),
            None,
            None,
            Some(Box::new(otp)),
            Some(Box::new(mci)),
            None,
            None,
            None,
            None,
        );

        let mut mcu_cpu = McuCpu::new(McuBusLogger::new(auto_root_bus), clock, pic);
        mcu_cpu.register_events();

        let mut m = ModelEmulated {
            output,
            caliptra_cpu,
            mcu_cpu,
            soc_to_caliptra_bus,
            caliptra_trace_fn: None,
            mcu_trace_fn: None,
            ready_for_fw,
            cpu_enabled,
            trace_path: trace_path_or_env(params.trace_path),
            _rom_image_tag: image_tag,
            iccm_image_tag: None,
            trng_mode,
            events_to_caliptra,
            events_from_caliptra,
            collected_events_from_caliptra: vec![],
        };
        // Turn tracing on if the trace path was set
        m.tracing_hint(true);

        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelEmulated"
    }

    fn trng_mode(&self) -> TrngMode {
        self.trng_mode
    }

    fn ready_for_fw(&self) -> bool {
        self.ready_for_fw.get()
    }
    fn apb_bus(&mut self) -> Self::TBus<'_> {
        EmulatedApbBus { model: self }
    }

    fn step(&mut self) {
        if self.cpu_enabled.get() {
            self.caliptra_cpu
                .step(self.caliptra_trace_fn.as_deref_mut());
            self.mcu_cpu.step(self.mcu_trace_fn.as_deref_mut());
        }
        // TODO: route events between MCU and Caliptra Core
        let events = self.events_from_caliptra.try_iter().collect::<Vec<_>>();
        self.collected_events_from_caliptra.extend(events);
    }

    fn output(&mut self) -> &mut Output {
        // In case the caller wants to log something, make sure the log has the
        // correct time.env::
        self.output.sink().set_now(self.caliptra_cpu.clock.now());
        &mut self.output
    }

    fn cover_fw_mage(&mut self, fw_image: &[u8]) {
        let iccm_image = &fw_image[IMAGE_MANIFEST_BYTE_SIZE..];
        self.iccm_image_tag = Some(hash_slice(iccm_image));
    }
    fn tracing_hint(&mut self, enable: bool) {
        if enable == self.caliptra_trace_fn.is_some() {
            // No change
            return;
        }
        self.caliptra_trace_fn = None;
        self.caliptra_cpu.bus.log = None;
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
        self.caliptra_cpu.bus.log = Some(log.clone());
        self.caliptra_trace_fn = Some(Box::new(move |pc, _instr| {
            writeln!(log, "pc=0x{pc:x}").unwrap();
        }))
    }

    fn ecc_error_injection(&mut self, mode: ErrorInjectionMode) {
        match mode {
            ErrorInjectionMode::None => {
                self.caliptra_cpu
                    .bus
                    .bus
                    .iccm
                    .ram()
                    .borrow_mut()
                    .error_injection = 0;
                self.caliptra_cpu.bus.bus.dccm.error_injection = 0;
            }
            ErrorInjectionMode::IccmDoubleBitEcc => {
                self.caliptra_cpu
                    .bus
                    .bus
                    .iccm
                    .ram()
                    .borrow_mut()
                    .error_injection = 2;
            }
            ErrorInjectionMode::DccmDoubleBitEcc => {
                self.caliptra_cpu.bus.bus.dccm.error_injection = 8;
            }
        }
    }

    fn set_axi_user(&mut self, _axi_user: u32) {
        unimplemented!();
    }

    fn warm_reset(&mut self) {
        self.caliptra_cpu.warm_reset();
        self.step();
    }

    // [TODO][CAP2] Should it be statically provisioned?
    fn put_firmware_in_rri(
        &mut self,
        firmware: &[u8],
        soc_manifest: Option<&[u8]>,
        mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        self.caliptra_cpu.bus.bus.dma.axi.recovery.cms_data = vec![firmware.to_vec()];
        if let Some(soc_manifest) = soc_manifest {
            self.caliptra_cpu
                .bus
                .bus
                .dma
                .axi
                .recovery
                .cms_data
                .push(soc_manifest.to_vec());
            if let Some(mcu_fw) = mcu_firmware {
                self.caliptra_cpu
                    .bus
                    .bus
                    .dma
                    .axi
                    .recovery
                    .cms_data
                    .push(mcu_fw.to_vec());
            }
        }
        Ok(())
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        self.collected_events_from_caliptra.drain(..).collect()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        self.events_to_caliptra.clone()
    }
}
