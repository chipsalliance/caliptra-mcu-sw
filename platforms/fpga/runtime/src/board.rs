// Licensed under the Apache-2.0 license

use crate::interrupts::FpgaPeripherals;
use crate::MCU_MEMORY_MAP;
use arrayvec::ArrayVec;
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_core::virtualizers::virtual_flash;
use capsules_runtime::flash_partition::FlashPartition;
use capsules_runtime::mctp::base_protocol::MessageType;
use core::ptr::{addr_of, addr_of_mut};
use kernel::capabilities;
use kernel::component::Component;
use kernel::errorcode;
use kernel::hil;
use kernel::hil::time::Alarm;
use kernel::platform::scheduler_timer::VirtualSchedulerTimer;
use kernel::platform::SyscallFilter;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process;
use kernel::scheduler::cooperative::CooperativeSched;
use kernel::syscall;
use kernel::utilities::registers::interfaces::ReadWriteable;
use kernel::{create_capability, debug, static_init};
use mcu_components::mbox_sram_component_static;
use mcu_components::mctp_driver_component_static;
use mcu_components::mctp_mux_component_static;
use mcu_components::{flash_partition_component_static, instantiate_flash_partitions};
use mcu_config_fpga::flash::STAGING_PARTITION;
use mcu_config_fpga::flash_partition_list_imaginary_flash;
use mcu_platforms_common::pmp_config::{PlatformPMPConfig, PlatformRegion};
use mcu_tock_veer::chip::{VeeRDefaultPeripherals, TIMERS};
use mcu_tock_veer::pic::Pic;
use mcu_tock_veer::pmp::VeeRProtectionMMLEPMP;
use mcu_tock_veer::timers::InternalTimers;
use registers_generated::mci;
use romtime::CaliptraSoC;
use romtime::StaticRef;
use rv32i::csr;

// These symbols are defined in the linker script.
extern "C" {
    /// Beginning of the ROM region containing app images.
    static _sapps: u8;
    /// End of the ROM region containing app images.
    static _eapps: u8;
    /// Beginning of the RAM region for app memory.
    static mut _sappmem: u8;
    /// End of the RAM region for app memory.
    static _eappmem: u8;
    /// The start of the kernel text (Included only for kernel PMP)
    static _stext: u8;
    /// The end of the kernel text (Included only for kernel PMP)
    static _etext: u8;
    /// The start of the kernel (Included only for kernel PMP)
    static _srom: u8;
    /// The end of the kernel (Included only for kernel PMP)
    static _erom: u8;
    /// The start of the app / storage flash (Included only for kernel PMP)
    static _sprog: u8;
    /// The end of the app / storage flash (Included only for kernel PMP)
    static _eprog: u8;
    /// The start of the kernel / app RAM (Included only for kernel PMP)
    static _ssram: u8;
    /// The end of the kernel / app RAM (Included only for kernel PMP)
    static _esram: u8;

    pub(crate) static _pic_vector_table: u8;
}

pub const NUM_PROCS: usize = 4;

// Actual memory for holding the active process structures. Need an empty list
// at least.
pub static mut PROCESSES: [Option<&'static dyn kernel::process::Process>; NUM_PROCS] =
    [None; NUM_PROCS];

pub type VeeRChip = mcu_tock_veer::chip::VeeR<'static, VeeRDefaultPeripherals<'static>>;

// Reference to the chip and peripherals for panic dumps and tests.
pub static mut CHIP: Option<&'static VeeRChip> = None;

// Static reference to process printer for panic dumps.
pub static mut PROCESS_PRINTER: Option<
    &'static capsules_system::process_printer::ProcessPrinterText,
> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut BOARD: Option<&'static kernel::Kernel> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut PLATFORM: Option<&'static VeeR> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut MAIN_CAP: Option<&dyn kernel::capabilities::MainLoopCapability> = None;

// How should the kernel respond when a process faults.
const FAULT_RESPONSE: capsules_system::process_policies::PanicFaultPolicy =
    capsules_system::process_policies::PanicFaultPolicy {};

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x2000] = [0; 0x2000];
#[no_mangle]
pub static mut PIC: Pic = Pic::new(MCU_MEMORY_MAP.pic_offset);

/// A structure representing this platform that holds references to all
/// capsules for this platform.
struct VeeR {
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        VirtualMuxAlarm<'static, InternalTimers<'static>>,
    >,
    console: &'static capsules_core::console::Console<'static>,
    lldb: &'static capsules_core::low_level_debug::LowLevelDebug<
        'static,
        capsules_core::virtualizers::virtual_uart::UartDevice<'static>,
    >,
    scheduler: &'static CooperativeSched<'static>,
    scheduler_timer:
        &'static VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>,
    mctp_spdm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_secure_spdm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_pldm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_caliptra: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    // active_image_par: &'static capsules_runtime::flash_partition::FlashPartition<'static>,
    // recovery_image_par: &'static capsules_runtime::flash_partition::FlashPartition<'static>,
    staging_partition: [Option<&'static FlashPartition<'static>>; 1],
    mailbox: &'static capsules_runtime::mailbox::Mailbox<
        'static,
        VirtualMuxAlarm<'static, InternalTimers<'static>>,
    >,
    mci: &'static capsules_runtime::mci::Mci,
    mcu_mbox1_staging_sram: &'static capsules_runtime::mbox_sram::MboxSram<
        'static,
        VirtualMuxAlarm<'static, InternalTimers<'static>>,
    >,
    otp: &'static capsules_runtime::otp::Otp,
    system: &'static capsules_runtime::system::System<'static, FpgaExiter>,
    dma: &'static capsules_emulator::dma::Dma<'static>,
}

/// Mapping of integer syscalls to objects that implement syscalls.
impl SyscallDriverLookup for VeeR {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::low_level_debug::DRIVER_NUM => f(Some(self.lldb)),
            capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM => f(Some(self.mctp_spdm)),
            capsules_runtime::mctp::driver::MCTP_SECURE_SPDM_DRIVER_NUM => {
                f(Some(self.mctp_secure_spdm))
            }
            capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM => f(Some(self.mctp_pldm)),
            capsules_runtime::mctp::driver::MCTP_CALIPTRA_DRIVER_NUM => f(Some(self.mctp_caliptra)),
            // capsules_runtime::flash_partition::ACTIVE_IMAGE_PAR_DRIVER_NUM => {
            //     f(Some(self.active_image_par))
            // }
            // capsules_runtime::flash_partition::RECOVERY_IMAGE_PAR_DRIVER_NUM => {
            //     f(Some(self.recovery_image_par))
            // }
            mcu_config_fpga::flash::DRIVER_NUM_EMULATED_FLASH_CTRL => {
                if let Some(partition) = self.staging_partition[0] {
                    if partition.get_driver_num() == driver_num {
                        return f(Some(partition));
                    } else {
                        return f(None);
                    }
                }
                return f(None);
            }
            capsules_runtime::mailbox::DRIVER_NUM => f(Some(self.mailbox)),
            capsules_runtime::mci::DRIVER_NUM => f(Some(self.mci)),
            capsules_runtime::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM => {
                f(Some(self.mcu_mbox1_staging_sram))
            }
            capsules_runtime::otp::DRIVER_NUM => f(Some(self.otp)),
            capsules_runtime::system::DRIVER_NUM => f(Some(self.system)),
            capsules_emulator::dma::DMA_CTRL_DRIVER_NUM => f(Some(self.dma)),
            _ => f(None),
        }
    }
}

struct Filter {}

impl SyscallFilter for Filter {
    fn filter_syscall(
        &self,
        _process: &dyn process::Process,
        _syscall: &syscall::Syscall,
    ) -> Result<(), errorcode::ErrorCode> {
        // Uncomment this to enable syscall logging
        //romtime::println!("Syscall: {:?}", syscall);
        Ok(())
    }
}

impl KernelResources<VeeRChip> for VeeR {
    type SyscallDriverLookup = Self;
    type SyscallFilter = Filter;
    type ProcessFault = ();
    type Scheduler = CooperativeSched<'static>;
    type SchedulerTimer = VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &Filter {}
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        self.scheduler_timer
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

pub(crate) struct FpgaWriter {}
pub(crate) static mut FPGA_WRITER: FpgaWriter = FpgaWriter {};

impl core::fmt::Write for FpgaWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

const FPGA_UART_OUTPUT: *mut u32 = 0xa401_1014 as *mut u32;

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
        }
    }
}

pub(crate) struct FpgaExiter {}
pub(crate) static mut FPGA_EXITER: FpgaExiter = FpgaExiter {};
impl romtime::Exit for FpgaExiter {
    fn exit(&mut self, code: u32) {
        exit_fpga(code)
    }
}

/// Exit the FPGA
pub fn exit_fpga(exit_code: u32) -> ! {
    // Safety: This is a safe memory address to write to for exiting the FPGA.
    unsafe {
        // By writing to this address we can exit the FPGA.
        let b = if exit_code == 0 { 0xff } else { 0x01 };
        core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
    }
    loop {}
}

/// Main function called after RAM initialized.
///
/// # Safety
/// Accesses memory, memory-mapped registers and CSRs.
pub unsafe fn main() {
    print_to_console("[mcu-runtime] Hello from MCU runtime\n");
    // only machine mode
    rv32i::configure_trap_handler();

    // TODO: remove this when the emulator-specific pieces are moved to
    // platform/emulator/runtime
    #[allow(static_mut_refs)]
    romtime::set_printer(&mut FPGA_WRITER);
    #[allow(static_mut_refs)]
    romtime::set_exiter(&mut FPGA_EXITER);

    // Set up memory protection immediately after setting the trap handler, to
    // ensure that much of the board initialization routine runs with ePMP
    // protection.

    // Define platform-specific memory regions
    let mut platform_regions = ArrayVec::<PlatformRegion, 12>::new();

    // Kernel text region (read + execute)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_srom),
        size: addr_of!(_erom) as usize - addr_of!(_srom) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: false,
        execute: true,
    });

    // Read-only region (ROM)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_sprog),
        size: addr_of!(_eprog) as usize - addr_of!(_sprog) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: false,
        execute: false,
    });

    // Data region (SRAM)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_ssram),
        size: addr_of!(_esram) as usize - addr_of!(_ssram) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    platform_regions.push(PlatformRegion {
        start_addr: MCU_MEMORY_MAP.dccm_offset as *const u8,
        size: MCU_MEMORY_MAP.dccm_size as usize,
        is_mmio: false, // DCCM is memory, not MMIO
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // User-accessible MMIO (FPGA peripherals and UART)
    platform_regions.push(PlatformRegion {
        start_addr: 0xa401_0000 as *const u8,
        size: 0x2000,
        is_mmio: true,
        user_accessible: true,
        read: true,
        write: true,
        execute: false,
    });

    // AXICDMA
    platform_regions.push(PlatformRegion {
        start_addr: registers_generated::axicdma::AXICDMA_ADDR as *const u8,
        size: 0x1000,
        is_mmio: true,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // Staging SRAM
    platform_regions.push(PlatformRegion {
        start_addr: MCU_MEMORY_MAP.staging_sram_offset as *const u8,
        size: MCU_MEMORY_MAP.staging_sram_size as usize,
        is_mmio: true,
        user_accessible: true,
        read: true,
        write: true,
        execute: false,
    });

    // Create PMP configuration
    let config = PlatformPMPConfig {
        regions: &platform_regions,
        memory_map: &MCU_MEMORY_MAP,
    };

    romtime::println!("[mcu-runtime] Set PMP");
    // Generate PMP region list using the shared infrastructure
    let pmp_regions = mcu_platforms_common::pmp_config::create_pmp_regions(config)
        .expect("Failed to create PMP regions");

    romtime::println!("[mcu-runtime] Enabling PMP");
    romtime::println!("PMP Regions:");
    romtime::println!("{}", pmp_regions);
    let epmp = VeeRProtectionMMLEPMP::new(pmp_regions).unwrap();
    romtime::println!("[mcu-runtime] Set PMP done");

    // initialize capabilities
    let process_mgmt_cap = create_capability!(capabilities::ProcessManagementCapability);
    let memory_allocation_cap = create_capability!(capabilities::MemoryAllocationCapability);

    let main_loop_cap = create_capability!(capabilities::MainLoopCapability);
    romtime::println!("[mcu-runtime] Capabilities created");
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&*addr_of!(PROCESSES)));
    romtime::println!("[mcu-runtime] Kernel created");

    // Configure kernel debug gpios as early as possible
    kernel::debug::assign_gpios(None, None, None);
    romtime::println!("[mcu-runtime] GPIOs assigned");

    let timers = &*addr_of!(TIMERS);
    romtime::println!("[mcu-runtime] Timers created");

    // Create a shared virtualization mux layer on top of a single hardware
    // alarm.
    let mux_alarm = static_init!(MuxAlarm<'static, InternalTimers>, MuxAlarm::new(timers));
    hil::time::Alarm::set_alarm_client(timers, mux_alarm);
    romtime::println!("[mcu-runtime] MuxAlarm created");

    // Alarm
    let virtual_alarm_user = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    virtual_alarm_user.setup();
    romtime::println!("[mcu-runtime] VirtualMuxAlarm created");

    let systick_virtual_alarm = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    systick_virtual_alarm.setup();
    romtime::println!("[mcu-runtime] SystickMuxAlarm created");

    let alarm = static_init!(
        capsules_core::alarm::AlarmDriver<'static, VirtualMuxAlarm<'static, InternalTimers>>,
        capsules_core::alarm::AlarmDriver::new(
            virtual_alarm_user,
            board_kernel.create_grant(capsules_core::alarm::DRIVER_NUM, &memory_allocation_cap)
        )
    );
    hil::time::Alarm::set_alarm_client(virtual_alarm_user, alarm);
    romtime::println!("[mcu-runtime] Alarm initialized");

    let mbox_dma_driver = static_init!(
        dma_driver::nodma::NoDMA<'static, InternalTimers<'static>>,
        dma_driver::nodma::NoDMA::new(mux_alarm)
    );
    let mbox_staging_addr = if cfg!(feature = "hw-2-1") {
        Some(MCU_MEMORY_MAP.staging_sram_offset as u64)
    } else {
        None
    };

    let mailbox = mcu_components::mailbox::MailboxComponent::new(
        board_kernel,
        capsules_runtime::mailbox::DRIVER_NUM,
        mux_alarm,
        mbox_dma_driver,
    )
    .finalize(mcu_components::mailbox_component_static!(
        InternalTimers<'static>,
        Some(MCU_MEMORY_MAP.soc_offset),
        Some(MCU_MEMORY_MAP.soc_offset),
        Some(MCU_MEMORY_MAP.mbox_offset),
        mbox_staging_addr
    ));

    mailbox.alarm.set_alarm_client(mailbox);
    romtime::println!("[mcu-runtime] Mailbox initialized");

    let mci_regs =
        unsafe { romtime::StaticRef::new(MCU_MEMORY_MAP.mci_offset as *const mci::regs::Mci) };
    let fpga_peripherals = static_init!(FpgaPeripherals, FpgaPeripherals::new(mux_alarm, mci_regs));
    fpga_peripherals.init();
    let peripherals = static_init!(
        VeeRDefaultPeripherals,
        VeeRDefaultPeripherals::new(fpga_peripherals, mux_alarm, &MCU_MEMORY_MAP, mci_regs)
    );
    romtime::println!("[mcu-runtime] Peripherals created");

    let chip = static_init!(VeeRChip, mcu_tock_veer::chip::VeeR::new(peripherals, epmp));
    romtime::println!(
        "[mcu-runtime] Initializing chip with PIC vector table set to {:x}",
        addr_of!(_pic_vector_table) as u32
    );
    chip.init(addr_of!(_pic_vector_table) as u32);
    CHIP = Some(chip);
    romtime::println!("[mcu-runtime] Chip initialized");

    // Create a shared UART channel for the console and for kernel debug.
    // TODO: add a new UART for the FPGA
    let uart_mux = components::console::UartMuxComponent::new(&fpga_peripherals.uart, 115200)
        .finalize(components::uart_mux_component_static!());
    romtime::println!("[mcu-runtime] UART initialized");

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux)
        .finalize(components::debug_writer_component_static!());
    romtime::println!("[mcu-runtime] DebugWriter initialized");

    let lldb = components::lldb::LowLevelDebugComponent::new(
        board_kernel,
        capsules_core::low_level_debug::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::low_level_debug_component_static!());
    romtime::println!("[mcu-runtime] LowLevelDebugComponent initialized");

    // Setup the console.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());
    romtime::println!("[mcu-runtime] Console initialized");

    // Create a process printer for panic.
    if cfg!(feature = "debug") {
        let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
            .finalize(components::process_printer_text_component_static!());
        PROCESS_PRINTER = Some(process_printer);
        romtime::println!("[mcu-runtime] ProcessPrinter initialized");
    }

    let mux_mctp = mcu_components::mux_mctp::MCTPMuxComponent::new(&peripherals.i3c, mux_alarm)
        .finalize(mctp_mux_component_static!(InternalTimers, MCTPI3CBinding));
    romtime::println!("[mcu-runtime] MCTP mux initialized");

    let mctp_spdm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Spdm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));
    romtime::println!("[mcu-runtime] MCTP SPDM driver component initialized");

    let mctp_secure_spdm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SECURE_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::SecureSpdm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));
    romtime::println!("[mcu-runtime] MCTP Secure SPDM driver component initialized");

    let mctp_pldm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Pldm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));
    romtime::println!("[mcu-runtime] MCTP PLDM driver component initialized");

    let mctp_caliptra = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_CALIPTRA_DRIVER_NUM,
        mux_mctp,
        MessageType::Caliptra,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));
    romtime::println!("[mcu-runtime] MCTP Caliptra driver component initialized");

    let mci = mcu_components::mci::MciComponent::new(
        board_kernel,
        capsules_runtime::mci::DRIVER_NUM,
        &peripherals.mci,
    )
    .finalize(kernel::static_buf!(capsules_runtime::mci::Mci));
    romtime::println!("[mcu-runtime] MCI driver component initialized");

    let mcu_mbox1_staging_sram = mcu_components::mbox_sram::MboxSramComponent::new(
        peripherals.mci.registers.clone(),
        board_kernel,
        capsules_runtime::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
        core::slice::from_raw_parts_mut(
            (MCU_MEMORY_MAP.mci_offset + mcu_mbox_driver::MCU_MBOX1_SRAM_OFFSET) as *mut u32,
            4 * 1024, // Allocate 4KB
        ),
        mux_alarm,
    )
    .finalize(mbox_sram_component_static!(InternalTimers<'static>));
    romtime::println!("[mcu-runtime] MCU Mbox1 SRAM component initialized");

    let mux_mcu_mbox_flash =
        components::flash::FlashMuxComponent::new(&fpga_peripherals.flash_ctrl).finalize(
            components::flash_mux_component_static!(flash_ctrl_fpga::EmulatedFlashCtrl),
        );
    let mut staging_partition: [Option<&'static FlashPartition<'static>>; 1] = [None; 1];
    instantiate_flash_partitions!(
        flash_partition_list_imaginary_flash,
        staging_partition,
        board_kernel,
        mux_mcu_mbox_flash,
        flash_ctrl_fpga::EmulatedFlashCtrl
    );
    romtime::println!("[mcu-runtime] Flash partition component initialized");

    let total_heks = 8;
    let otp = mcu_components::otp::OtpComponent::new(
        board_kernel,
        capsules_runtime::otp::DRIVER_NUM,
        total_heks,
        &peripherals.otp,
    )
    .finalize(kernel::static_buf!(capsules_runtime::otp::Otp));
    romtime::println!("[mcu-runtime] OTP component initialized");

    #[allow(static_mut_refs)]
    let system = mcu_components::system::SystemComponent::new(unsafe { &mut FPGA_EXITER })
        .finalize(kernel::static_buf!(
            capsules_runtime::system::System<'static, FpgaExiter>
        ));

    let dma = mcu_components::dma::DmaComponent::new(
        &fpga_peripherals.dma,
        board_kernel,
        capsules_emulator::dma::DMA_CTRL_DRIVER_NUM,
    )
    .finalize(kernel::static_buf!(capsules_emulator::dma::Dma<'static>));

    peripherals.init();
    romtime::println!("[mcu-runtime] Peripherals initialized");

    // Need to enable all interrupts for Tock Kernel
    chip.enable_pic_interrupts();
    chip.enable_timer_interrupts();

    // enable interrupts globally
    csr::CSR
        .mie
        .modify(csr::mie::mie::mext::SET + csr::mie::mie::msoft::SET + csr::mie::mie::BIT29::SET);
    csr::CSR.mstatus.modify(csr::mstatus::mstatus::mie::SET);

    debug!("MUX MCTP enable");
    mux_mctp.enable();

    debug!("MCU initialization complete.");
    debug!("Entering main loop.");

    let scheduler =
        components::sched::cooperative::CooperativeComponent::new(&*addr_of!(PROCESSES))
            .finalize(components::cooperative_component_static!(NUM_PROCS));

    let scheduler_timer = static_init!(
        VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>,
        VirtualSchedulerTimer::new(systick_virtual_alarm)
    );

    let veer = static_init!(
        VeeR,
        VeeR {
            alarm,
            console,
            lldb,
            scheduler,
            scheduler_timer,
            mctp_spdm,
            mctp_secure_spdm,
            mctp_pldm,
            mctp_caliptra,
            //active_image_par,
            //recovery_image_par,
            staging_partition,
            mailbox,
            mci,
            mcu_mbox1_staging_sram,
            otp,
            system,
            dma,
        }
    );

    kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            addr_of!(_sapps),
            addr_of!(_eapps) as usize - addr_of!(_sapps) as usize,
        ),
        core::slice::from_raw_parts_mut(
            addr_of_mut!(_sappmem),
            addr_of!(_eappmem) as usize - addr_of!(_sappmem) as usize,
        ),
        &mut *addr_of_mut!(PROCESSES),
        &FAULT_RESPONSE,
        &process_mgmt_cap,
    )
    .unwrap_or_else(|err| {
        debug!("Error loading processes!");
        debug!("{:?}", err);
    });

    #[cfg(any(
        feature = "test-flash-ctrl-read-write-page",
        feature = "test-flash-ctrl-erase-page",
        feature = "test-flash-storage-read-write",
        feature = "test-flash-storage-erase"
    ))]
    {
        PLATFORM = Some(veer);
        MAIN_CAP = Some(&create_capability!(capabilities::MainLoopCapability));
        BOARD = Some(board_kernel);
    }

    // Run any requested test
    let exit = if cfg!(feature = "test-exit-immediately") {
        debug!("Executing test-exit-immediately");
        Some(0)
    } else if cfg!(feature = "test-i3c-simple") {
        debug!("Executing test-i3c-simple");
        //crate::tests::i3c_target_test::test_i3c_simple()
        None
    } else if cfg!(feature = "test-i3c-constant-writes") {
        debug!("Executing test-i3c-constant-writes");
        //crate::tests::i3c_target_test::test_i3c_constant_writes()
        None
    } else {
        None
    };

    #[cfg(feature = "test-mctp-capsule-loopback")]
    {
        debug!("Executing test-mctp-capsule-loopback");
        crate::tests::mctp_test::test_mctp_capsule_loopback(mux_mctp);
    }

    if let Some(exit) = exit {
        crate::io::exit_fpga(exit);
    }

    // Disable WDT1 before running the loop
    let mci: StaticRef<mci::regs::Mci> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.mci_offset as *const mci::regs::Mci) };
    let mci_wdt = romtime::Mci::new(mci);
    mci_wdt.disable_wdt();

    // Enable MCI Interrupts
    mci.intr_block_rf_global_intr_en_r
        .modify(mci::bits::GlobalIntrEnT::NotifEn::SET + mci::bits::GlobalIntrEnT::ErrorEn::SET);
    mci.intr_block_rf_notif0_intr_en_r
        .modify(mci::bits::Notif0IntrEnT::NotifCptraMcuResetReqEn::SET);

    board_kernel.kernel_loop(veer, chip, None::<&kernel::ipc::IPC<0>>, &main_loop_cap);
}

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
pub fn run_kernel_op(loops: usize) {
    unsafe {
        for _i in 0..loops {
            BOARD.unwrap().kernel_loop_operation(
                PLATFORM.unwrap(),
                CHIP.unwrap(),
                None::<&kernel::ipc::IPC<0>>,
                true,
                MAIN_CAP.unwrap(),
            );
        }
    }
}
