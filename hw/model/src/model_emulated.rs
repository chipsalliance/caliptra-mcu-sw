// Licensed under the Apache-2.0 license

use crate::bus_logger::BusLogger;
use crate::bus_logger::LogFile;
use crate::bus_logger_mcu::McuBusLogger;
use crate::trace_path_or_env;
use crate::InitParams;
use crate::McuHwModel;
use crate::Output;
use anyhow::Result;
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Event;
use caliptra_emu_cpu::CpuArgs;
use caliptra_emu_cpu::{Cpu as CaliptraCpu, InstrTracer as CaliptraInstrTracer};
use caliptra_emu_periph::ActionCb;
use caliptra_emu_periph::MailboxRequester;
use caliptra_emu_periph::ReadyForFwCb;
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, TbServicesCb};
use caliptra_hw_model::ModelError;
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;
use emulator_bus::BusConverter;
use emulator_bus::Clock as McuClock;
use emulator_cpu::{Cpu as McuCpu, InstrTracer as McuInstrTracer};
use emulator_periph::{I3c, I3cController, Mci, McuRootBus, McuRootBusArgs, Otp};
use emulator_registers_generated::root_bus::AutoRootBus;
use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

const DEFAULT_AXI_PAUSER: u32 = 0xaaaa_aaaa;

/// Emulated model
pub struct ModelEmulated {
    caliptra_cpu: CaliptraCpu<BusLogger<CaliptraRootBus>>,
    mcu_cpu: McuCpu<McuBusLogger<AutoRootBus>>,
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
        let pic = Rc::new(caliptra_emu_cpu::Pic::new());
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
        let _soc_to_caliptra_bus =
            root_bus.soc_to_caliptra_bus(MailboxRequester::SocUser(DEFAULT_AXI_PAUSER));
        let soc_to_caliptra_bus2 =
            root_bus.soc_to_caliptra_bus(MailboxRequester::SocUser(DEFAULT_AXI_PAUSER));
        let (events_to_caliptra, events_from_caliptra, caliptra_cpu) = {
            let mut cpu = CaliptraCpu::new(
                BusLogger::new(root_bus),
                clock.clone(),
                pic.clone(),
                CpuArgs::default(),
            );
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
        let pic = Rc::new(emulator_cpu::Pic::new());
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
        let mci = Mci::new(&clock.clone());

        let delegates: Vec<Box<dyn emulator_bus::Bus>> = vec![
            Box::new(mcu_root_bus),
            Box::new(BusConverter::new(Box::new(soc_to_caliptra_bus2))),
        ];

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
            None,
            None,
            Some(Box::new(otp)),
            None,
        );

        let mut mcu_cpu = McuCpu::new(McuBusLogger::new(auto_root_bus), clock, pic);
        mcu_cpu.register_events();

        let mut m = ModelEmulated {
            output,
            caliptra_cpu,
            mcu_cpu,
            caliptra_trace_fn: None,
            mcu_trace_fn: None,
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

    fn type_name(&self) -> &'static str {
        "ModelEmulated"
    }

    fn ready_for_fw(&self) -> bool {
        self.ready_for_fw.get()
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

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        self.collected_events_from_caliptra.drain(..).collect()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        self.events_to_caliptra.clone()
    }
}

#[cfg(test)]
mod test {
    use crate::{DefaultHwModel, InitParams, McuHwModel};

    #[test]
    fn test_new_unbooted() {
        let mcu_rom = mcu_builder::rom_build(None, "").expect("Could not build MCU ROM");
        let mcu_runtime = &mcu_builder::runtime_build_with_apps(&[], None, false, None, None)
            .expect("Could not build MCU runtime");
        let mut caliptra_builder =
            mcu_builder::CaliptraBuilder::new(true, None, None, None, None, None, None);
        let caliptra_rom = caliptra_builder
            .get_caliptra_rom()
            .expect("Could not build Caliptra ROM");
        let caliptra_fw = caliptra_builder
            .get_caliptra_fw()
            .expect("Could not build Caliptra FW bundle");
        let _vendor_pk_hash = caliptra_builder
            .get_vendor_pk_hash()
            .expect("Could not get vendor PK hash");

        let caliptra_rom = std::fs::read(caliptra_rom).unwrap();
        let caliptra_fw = std::fs::read(caliptra_fw).unwrap();
        let mcu_rom = std::fs::read(mcu_rom).unwrap();
        let mcu_runtime = std::fs::read(mcu_runtime).unwrap();

        let mut model = DefaultHwModel::new_unbooted(InitParams {
            caliptra_rom: &caliptra_rom,
            caliptra_firmware: &caliptra_fw,
            mcu_rom: &mcu_rom,
            mcu_firmware: &mcu_runtime,
            ..Default::default()
        })
        .unwrap();
        for _ in 0..1000 {
            model.step();
        }
    }
}
