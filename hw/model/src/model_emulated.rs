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
use anyhow::bail;
use anyhow::Result;
use caliptra_api::SocManager;
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusError;
use caliptra_emu_bus::BusMmio;
use caliptra_emu_bus::Ram;
use caliptra_emu_bus::{Clock, Event};
use caliptra_emu_cpu::CpuOrgArgs;
use caliptra_emu_cpu::{Cpu, CpuArgs, InstrTracer, Pic};
use caliptra_emu_periph::CaliptraRootBus as CaliptraMainRootBus;
use caliptra_emu_periph::SocToCaliptraBus;
use caliptra_emu_types::RvAddr;
use caliptra_emu_types::RvData;
use caliptra_emu_types::RvSize;
use caliptra_hw_model::Output;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;
use emulator_bmc::Bmc;
use emulator_caliptra::start_caliptra;
use emulator_caliptra::BytesOrPath;
use emulator_caliptra::StartCaliptraArgs;
use emulator_periph::DummyFlashCtrl;
use emulator_periph::LcCtrl;
use emulator_periph::McuRootBusOffsets;
use emulator_periph::NetworkRootBus;
use emulator_periph::{I3c, I3cController, Mci, McuRootBus, McuRootBusArgs, Otp, OtpArgs};
use emulator_registers_generated::axicdma::AxicdmaPeripheral;
use emulator_registers_generated::primary_flash::PrimaryFlashPeripheral;
use emulator_registers_generated::root_bus::AutoRootBus;
use mcu_config::{McuMemoryMap, McuStraps};
use mcu_rom_common::McuBootMilestones;
use mcu_testing_common::i3c_socket_server::start_i3c_socket;
use mcu_testing_common::{MCU_RUNNING, MCU_RUNTIME_STARTED};
use registers_generated::fuses;
use romtime::LifecycleControllerState;
use semver::Version;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread::JoinHandle;

const BOOT_CYCLES: u64 = 100_000_000;

/// Emulated model
pub struct ModelEmulated {
    cpu: Cpu<BusLogger<AutoRootBus>>,
    caliptra_cpu: Cpu<CaliptraMainRootBus>,
    network_cpu: Option<Cpu<NetworkRootBus>>,
    network_uart_output: Option<Rc<RefCell<Vec<u8>>>>,
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
    bmc: Option<Bmc>,
    i3c_port: Option<u16>,
    i3c_controller: I3cController,
    i3c_address: Option<u8>,
    i3c_controller_join_handle: Option<JoinHandle<()>>,
    dot_flash: Rc<RefCell<Ram>>,
    otp_partitions: Rc<RefCell<Vec<u8>>>,
    check_booted_to_runtime: bool,
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

        let ready_for_fw = Rc::new(Cell::new(false));

        let cpu_enabled = Rc::new(Cell::new(false));

        let output = Output::new(params.log_writer);

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

        let mut i3c_controller = if let Some(i3c_port) = params.i3c_port {
            let (rx, tx) = start_i3c_socket(&MCU_RUNNING, i3c_port);
            I3cController::new(rx, tx)
        } else {
            I3cController::default()
        };

        let i3c_irq = pic.register_irq(McuRootBus::I3C_IRQ);

        let dma_ram = mcu_root_bus.ram.clone();
        let rom_sram = mcu_root_bus.rom_sram.clone();
        let direct_read_flash = mcu_root_bus.direct_read_flash.clone();
        let dot_flash = mcu_root_bus.dot_flash.clone();

        // Use HW 2.1.0 for flash-based boot, otherwise 2.0.0
        let hw_version = if params.flash_boot {
            Version::new(2, 1, 0)
        } else {
            Version::new(2, 0, 0)
        };

        let i3c = I3c::new(&clock.clone(), &mut i3c_controller, i3c_irq, hw_version);

        let i3c_dynamic_address = i3c.get_dynamic_address().unwrap();

        let otp_size = fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE;
        let mut otp_mem = if let Some(initial_otp) = params.otp_memory {
            // Start with provided OTP memory contents, extended to full size if needed
            let mut mem = initial_otp.to_vec();
            mem.resize(otp_size, 0);
            mem
        } else {
            vec![0u8; otp_size]
        };
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

        let lc = LcCtrl::new();

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

        // Get the partitions reference before passing OTP to the bus
        let otp_partitions = otp.partitions_ref();

        let create_flash_controller =
            |default_path: &str,
             error_irq: u8,
             event_irq: u8,
             initial_content: Option<&[u8]>,
             direct_read_region: Option<Rc<RefCell<caliptra_emu_bus::Ram>>>| {
                // Use a temporary file for flash storage if we're running a test
                let flash_file = Some(PathBuf::from(default_path));

                DummyFlashCtrl::new(
                    &clock.clone(),
                    direct_read_region,
                    flash_file,
                    pic.register_irq(error_irq),
                    pic.register_irq(event_irq),
                    initial_content,
                )
                .unwrap()
            };

        let mut primary_flash_controller = create_flash_controller(
            "primary_flash",
            McuRootBus::PRIMARY_FLASH_CTRL_ERROR_IRQ,
            McuRootBus::PRIMARY_FLASH_CTRL_EVENT_IRQ,
            params.primary_flash_initial_contents.as_deref(),
            Some(direct_read_flash.clone()),
        );
        primary_flash_controller.set_dma_rom_sram(rom_sram.clone());

        let mut secondary_flash_controller = create_flash_controller(
            "secondary_flash",
            McuRootBus::SECONDARY_FLASH_CTRL_ERROR_IRQ,
            McuRootBus::SECONDARY_FLASH_CTRL_EVENT_IRQ,
            None,
            None,
        );
        secondary_flash_controller.set_dma_rom_sram(rom_sram.clone());

        let mut dma_ctrl = emulator_periph::AxiCDMA::new(
            &clock.clone(),
            pic.register_irq(McuRootBus::DMA_ERROR_IRQ),
            pic.register_irq(McuRootBus::DMA_EVENT_IRQ),
            Some(mcu_root_bus.external_test_sram.clone()),
            Some(mcu_root_bus.mcu_mailbox0.clone()),
            Some(mcu_root_bus.mcu_mailbox1.clone()),
        )
        .unwrap();

        emulator_periph::AxiCDMA::set_dma_ram(&mut dma_ctrl, dma_ram.clone());

        let device_lifecycle: Option<String> = match params.lifecycle_controller_state {
            Some(LifecycleControllerState::Dev) => Some("manufacturing".into()),
            Some(LifecycleControllerState::Raw) => Some("unprovisioned".into()),
            _ => Some("production".into()),
        };

        let req_idevid_csr: Option<bool> = match params.lifecycle_controller_state {
            Some(LifecycleControllerState::Dev) => Some(true),
            _ => None,
        };

        // Use MCU recovery interface when flash-based boot is enabled
        let use_mcu_recovery_interface = params.flash_boot;

        let (mut caliptra_cpu, soc_to_caliptra, soc_to_caliptra_bus, ext_mci) =
            start_caliptra(&StartCaliptraArgs {
                rom: BytesOrPath::Bytes(params.caliptra_rom.to_vec()),
                device_lifecycle,
                req_idevid_csr,
                use_mcu_recovery_interface,
                extra_soc_bus: Some(
                    params
                        .caliptra_soc_axi_user
                        .unwrap_or(McuStraps::default().axi_user1),
                ),
            })
            .expect("Failed to start Caliptra CPU");
        let soc_to_caliptra_bus = soc_to_caliptra_bus.unwrap();

        let mcu_mailbox0 = mcu_root_bus.mcu_mailbox0.clone();
        let mcu_mailbox1 = mcu_root_bus.mcu_mailbox1.clone();

        let mci_irq = pic.register_irq(McuRootBus::MCI_IRQ);
        // Set flash boot wire (bit 29 of generic_input_wires[1]) if flash boot is requested
        let mci_generic_input_wires = if params.flash_boot {
            [0, 1 << 29]
        } else {
            [0, 0]
        };
        let mci = Mci::new(
            &clock.clone(),
            ext_mci,
            Rc::new(RefCell::new(mci_irq)),
            Some(mcu_mailbox0),
            Some(mcu_mailbox1),
            None,
            mci_generic_input_wires,
        );

        let delegates: Vec<Box<dyn caliptra_emu_bus::Bus>> =
            vec![Box::new(mcu_root_bus), Box::new(soc_to_caliptra)];

        let auto_root_bus = AutoRootBus::new(
            delegates,
            None,
            Some(Box::new(i3c)),
            Some(Box::new(primary_flash_controller)),
            Some(Box::new(secondary_flash_controller)),
            Some(Box::new(mci)),
            None,
            None,
            Some(Box::new(otp)),
            Some(Box::new(lc)),
            None,
            None,
            None,
            Some(Box::new(dma_ctrl)),
        );

        let args = CpuArgs {
            org: CpuOrgArgs {
                reset_vector: McuMemoryMap::default().rom_offset,
                ..Default::default()
            },
        };
        let mut cpu = Cpu::new(BusLogger::new(auto_root_bus), clock, pic, args);

        if let Some(stack_info) = params.stack_info {
            cpu.with_stack_info(stack_info);
        }

        let (caliptra_event_sender, caliptra_event_receiver) = caliptra_cpu.register_events();
        let (mcu_event_sender, mcu_event_receiver) = cpu.register_events();

        // Use MCU recovery interface (I3C) when flash-based boot is enabled,
        // otherwise use BMC recovery interface
        let use_flash_based_boot = params.flash_boot;
        let bmc = if use_flash_based_boot {
            // Connect event channels to I3C peripheral for MCU recovery interface
            cpu.bus
                .bus
                .i3c_periph
                .as_mut()
                .unwrap()
                .periph
                .register_event_channels(
                    caliptra_event_sender,
                    caliptra_event_receiver,
                    mcu_event_sender,
                    mcu_event_receiver,
                );
            None
        } else {
            // Use BMC recovery interface emulator
            let mut bmc = Bmc::new(
                caliptra_event_sender,
                caliptra_event_receiver,
                mcu_event_sender,
                mcu_event_receiver,
            );
            // Push recovery images to BMC for streaming boot
            if !params.caliptra_firmware.is_empty() {
                bmc.push_recovery_image(params.caliptra_firmware.to_vec());
            }
            if !params.soc_manifest.is_empty() {
                bmc.push_recovery_image(params.soc_manifest.to_vec());
            }
            if !params.mcu_firmware.is_empty() {
                bmc.push_recovery_image(params.mcu_firmware.to_vec());
            }
            Some(bmc)
        };

        let (events_to_caliptra, events_from_caliptra) = mpsc::channel();

        // Initialize network CPU if network_rom is provided
        let (network_cpu, network_uart_output) = if !params.network_rom.is_empty() {
            let network_clock = Rc::new(Clock::new());
            let network_pic = Rc::new(Pic::new());
            let network_uart_output = Rc::new(RefCell::new(Vec::new()));

            let network_args = emulator_periph::NetworkRootBusArgs {
                rom: params.network_rom.to_vec(),
                pic: network_pic.clone(),
                clock: network_clock.clone(),
                uart_output: Some(network_uart_output.clone()),
                ..Default::default()
            };

            let network_root_bus =
                NetworkRootBus::new(network_args).expect("Failed to create NetworkRootBus");

            let mut network_cpu = Cpu::new(
                network_root_bus,
                network_clock,
                network_pic,
                emulator_consts::NETWORK_CPU_ARGS,
            );
            network_cpu.write_pc(emulator_consts::NETWORK_ROM_ORG);

            (Some(network_cpu), Some(network_uart_output))
        } else {
            (None, None)
        };

        let mut m = ModelEmulated {
            caliptra_cpu,
            network_cpu,
            network_uart_output,
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
            bmc,
            i3c_port: params.i3c_port,
            i3c_controller,
            i3c_address: Some(i3c_dynamic_address.into()),
            i3c_controller_join_handle: None,
            dot_flash,
            otp_partitions,
            check_booted_to_runtime: params.check_booted_to_runtime,
        };
        // Turn tracing on if the trace path was set
        m.tracing_hint(true);
        if let Some(dot_flash_data) = params.dot_flash_initial_contents.as_deref() {
            m.write_dot_flash(dot_flash_data)?;
        }

        Ok(m)
    }

    fn boot(&mut self) -> Result<()>
    where
        Self: Sized,
    {
        self.cpu_enabled.set(true);

        if self.check_booted_to_runtime {
            self.step_until(|hw| {
                hw.cycle_count() >= BOOT_CYCLES
                    || hw
                        .mci_boot_milestones()
                        .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
            });
            use std::io::Write;
            let mut w = std::io::Sink::default();
            if !self.output().peek().is_empty() {
                w.write_all(self.output().take(usize::MAX).as_bytes())
                    .unwrap();
            }
            assert!(self
                .mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));
            MCU_RUNTIME_STARTED.store(true, Ordering::Relaxed);
        }

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
            self.caliptra_cpu
                .step(self.caliptra_trace_fn.as_deref_mut());
            if let Some(bmc) = &mut self.bmc {
                bmc.step();
            }
            // Step network CPU if present
            if let Some(ref mut network_cpu) = self.network_cpu {
                network_cpu.step(None);
            }
        }
        let events = self.events_from_caliptra.try_iter().collect::<Vec<_>>();
        self.collected_events_from_caliptra.extend(events);
        if self.cycle_count() % mcu_testing_common::TICK_NOTIFY_TICKS == 0 {
            mcu_testing_common::update_ticks(self.cycle_count());
        }
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

    fn read_otp_memory(&self) -> Vec<u8> {
        self.otp_partitions.borrow().clone()
    }

    fn read_dot_flash(&self) -> Vec<u8> {
        self.dot_flash.borrow().data().to_vec()
    }

    fn write_dot_flash(&mut self, data: &[u8]) -> Result<()> {
        let mut flash = self.dot_flash.borrow_mut();
        let flash = flash.data_mut();
        if data.len() > flash.len() {
            bail!("Data length exceeds DOT flash size");
        }
        let len = data.len().min(flash.len());
        flash[..len].copy_from_slice(&data[..len]);
        Ok(())
    }

    fn mcu_manager(&mut self) -> impl McuManager {
        self
    }

    fn caliptra_soc_manager(&mut self) -> impl caliptra_api::SocManager {
        self
    }

    fn start_i3c_controller(&mut self) {
        if self.i3c_controller_join_handle.is_none() {
            self.i3c_controller_join_handle = Some(self.i3c_controller.start());
        }
    }

    fn i3c_port(&self) -> Option<u16> {
        self.i3c_port
    }

    fn i3c_address(&self) -> Option<u8> {
        self.i3c_address
    }

    fn has_network_cpu(&self) -> bool {
        self.network_cpu.is_some()
    }

    fn network_uart_output(&self) -> Option<String> {
        self.network_uart_output
            .as_ref()
            .map(|output| String::from_utf8_lossy(&output.borrow()).to_string())
    }

    fn warm_reset(&mut self) {
        self.cpu.warm_reset();
        self.step();
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

impl Drop for ModelEmulated {
    fn drop(&mut self) {
        MCU_RUNNING.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{InitParams, McuHwModel, ModelEmulated};

    #[test]
    fn test_new_unbooted() {
        let mcu_rom = mcu_builder::rom_build(None, None).expect("Could not build MCU ROM");
        let mcu_runtime = &mcu_builder::runtime_build_with_apps(&[], None, false, None, None)
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
        let soc_manifest = caliptra_builder.get_soc_manifest(None).unwrap();

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
        for _ in 0..100_000 {
            model.step();
        }
        use std::io::Write;
        let mut w = std::io::Sink::default();
        if !model.output().peek().is_empty() {
            w.write_all(model.output().take(usize::MAX).as_bytes())
                .unwrap();
        }
        assert!(model
            .mci_boot_milestones()
            .contains(McuBootMilestones::CPTRA_FUSES_WRITTEN));
    }
}
