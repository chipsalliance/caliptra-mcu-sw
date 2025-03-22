// Licensed under the Apache-2.0 license

use crate::chip::VeeRDefaultPeripherals;
use crate::chip::TIMERS;
use crate::components as runtime_components;
use crate::pmp::CodeRegion;
use crate::pmp::DataRegion;
use crate::pmp::KernelTextRegion;
use crate::pmp::MMIORegion;
use crate::pmp::VeeRProtectionMMLEPMP;
use crate::timers::InternalTimers;

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_core::virtualizers::virtual_flash;
use capsules_runtime::mctp::base_protocol::MessageType;
use core::ptr::{addr_of, addr_of_mut};
use kernel::capabilities;
use kernel::component::Component;
use kernel::hil;
use kernel::platform::scheduler_timer::VirtualSchedulerTimer;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::scheduler::cooperative::CooperativeSched;
use kernel::utilities::registers::interfaces::ReadWriteable;
use kernel::{create_capability, debug, static_init};
use rv32i::csr;
use rv32i::pmp::{NAPOTRegionSpec, TORRegionSpec};

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
    /// The start of the kernel / app / storage flash (Included only for kernel PMP)
    static _srom: u8;
    /// The end of the kernel / app / storage flash (Included only for kernel PMP)
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

pub type VeeRChip = crate::chip::VeeR<'static, VeeRDefaultPeripherals<'static>>;

// Reference to the chip for panic dumps.
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
    active_image_par: &'static capsules_runtime::flash_partition::FlashPartition<'static>,
    recovery_image_par: &'static capsules_runtime::flash_partition::FlashPartition<'static>,
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
            capsules_runtime::flash_partition::ACTIVE_IMAGE_PAR_DRIVER_NUM => {
                f(Some(self.active_image_par))
            }
            capsules_runtime::flash_partition::RECOVERY_IMAGE_PAR_DRIVER_NUM => {
                f(Some(self.recovery_image_par))
            }
            _ => f(None),
        }
    }
}

impl KernelResources<VeeRChip> for VeeR {
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type Scheduler = CooperativeSched<'static>;
    type SchedulerTimer = VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
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

// TODO: remove this dependence on the emulator when the emulator-specific
// pieces are moved to platform/emulator/runtime
pub(crate) struct EmulatorWriter {}
pub(crate) static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl core::fmt::Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
        }
    }
}

/// Main function called after RAM initialized.
///
/// # Safety
/// Accesses memory, memory-mapped registers and CSRs.
pub unsafe fn main() {
    // only machine mode
    rv32i::configure_trap_handler();

    // TODO: remove this when the emulator-specific pieces are moved to
    // platform/emulator/runtime
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }

    // Set up memory protection immediately after setting the trap handler, to
    // ensure that much of the board initialization routine runs with ePMP
    // protection.

    // fixed regions to allow user mode direct access to emulator control and UART
    let user_mmio = [MMIORegion(
        NAPOTRegionSpec::new(0x1000_0000 as *const u8, 0x1000_0000).unwrap(),
    )];
    // additional MMIO for machine only peripherals
    let machine_mmio = [
        MMIORegion(NAPOTRegionSpec::new(0x2000_0000 as *const u8, 0x2000_0000).unwrap()),
        MMIORegion(NAPOTRegionSpec::new(0x6000_0000 as *const u8, 0x1_0000).unwrap()),
    ];

    let epmp = VeeRProtectionMMLEPMP::new(
        CodeRegion(
            TORRegionSpec::new(core::ptr::addr_of!(_srom), core::ptr::addr_of!(_eprog)).unwrap(),
        ),
        DataRegion(
            TORRegionSpec::new(core::ptr::addr_of!(_ssram), core::ptr::addr_of!(_esram)).unwrap(),
        ),
        // use the MMIO for the PIC
        &user_mmio[..],
        &machine_mmio[..],
        KernelTextRegion(
            TORRegionSpec::new(core::ptr::addr_of!(_stext), core::ptr::addr_of!(_etext)).unwrap(),
        ),
    )
    .unwrap();

    // initialize capabilities
    let process_mgmt_cap = create_capability!(capabilities::ProcessManagementCapability);
    let memory_allocation_cap = create_capability!(capabilities::MemoryAllocationCapability);

    let main_loop_cap = create_capability!(capabilities::MainLoopCapability);
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&*addr_of!(PROCESSES)));

    // Configure kernel debug gpios as early as possible
    kernel::debug::assign_gpios(None, None, None);

    let timers = &*addr_of!(TIMERS);

    // Create a shared virtualization mux layer on top of a single hardware
    // alarm.
    let mux_alarm = static_init!(MuxAlarm<'static, InternalTimers>, MuxAlarm::new(timers));
    hil::time::Alarm::set_alarm_client(timers, mux_alarm);

    // Alarm
    let virtual_alarm_user = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    virtual_alarm_user.setup();

    let systick_virtual_alarm = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    systick_virtual_alarm.setup();

    let alarm = static_init!(
        capsules_core::alarm::AlarmDriver<'static, VirtualMuxAlarm<'static, InternalTimers>>,
        capsules_core::alarm::AlarmDriver::new(
            virtual_alarm_user,
            board_kernel.create_grant(capsules_core::alarm::DRIVER_NUM, &memory_allocation_cap)
        )
    );
    hil::time::Alarm::set_alarm_client(virtual_alarm_user, alarm);

    let peripherals = static_init!(
        VeeRDefaultPeripherals,
        VeeRDefaultPeripherals::new(mux_alarm)
    );

    let chip = static_init!(VeeRChip, crate::chip::VeeR::new(peripherals, epmp));
    chip.init();
    CHIP = Some(chip);

    // Create a shared UART channel for the console and for kernel debug.
    let uart_mux = components::console::UartMuxComponent::new(&peripherals.uart, 115200)
        .finalize(components::uart_mux_component_static!());

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux)
        .finalize(components::debug_writer_component_static!());

    let lldb = components::lldb::LowLevelDebugComponent::new(
        board_kernel,
        capsules_core::low_level_debug::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::low_level_debug_component_static!());

    // Setup the console.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // Create a process printer for panic.
    let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
        .finalize(components::process_printer_text_component_static!());
    PROCESS_PRINTER = Some(process_printer);

    let process_console = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        mux_alarm,
        process_printer,
        None,
    )
    .finalize(components::process_console_component_static!(
        InternalTimers
    ));
    let _ = process_console.start();

    let mux_mctp =
        runtime_components::mux_mctp::MCTPMuxComponent::new(&peripherals.i3c, mux_alarm).finalize(
            crate::mctp_mux_component_static!(InternalTimers, MCTPI3CBinding),
        );

    let mctp_spdm = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Spdm,
    )
    .finalize(crate::mctp_driver_component_static!(InternalTimers));

    let mctp_secure_spdm = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SECURE_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::SecureSpdm,
    )
    .finalize(crate::mctp_driver_component_static!(InternalTimers));

    let mctp_pldm = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Pldm,
    )
    .finalize(crate::mctp_driver_component_static!(InternalTimers));

    let mctp_caliptra = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_CALIPTRA_DRIVER_NUM,
        mux_mctp,
        MessageType::Caliptra,
    )
    .finalize(crate::mctp_driver_component_static!(InternalTimers));

    peripherals.init();

    // Create a mux for the physical flash controller
    let mux_main_flash = components::flash::FlashMuxComponent::new(&peripherals.main_flash_ctrl)
        .finalize(components::flash_mux_component_static!(
            flash_driver::flash_ctrl::EmulatedFlashCtrl
        ));

    // Instantiate a flashUser for image partition driver
    let image_par_fl_user = components::flash::FlashUserComponent::new(mux_main_flash).finalize(
        components::flash_user_component_static!(flash_driver::flash_ctrl::EmulatedFlashCtrl),
    );

    // Instantiate flash partition driver that is connected to mux flash via flashUser
    // TODO: Replace the start address and length with actual values from flash configuration.
    let active_image_par = runtime_components::flash_partition::FlashPartitionComponent::new(
        board_kernel,
        capsules_runtime::flash_partition::ACTIVE_IMAGE_PAR_DRIVER_NUM, // Driver number
        image_par_fl_user,
        0x0,        // Start address of the partition. Place holder for testing
        0x200_0000, // Length of the partition. Place holder for testing
    )
    .finalize(crate::flash_partition_component_static!(
        virtual_flash::FlashUser<'static, flash_driver::flash_ctrl::EmulatedFlashCtrl>,
        capsules_runtime::flash_partition::BUF_LEN
    ));

    // Create a mux for the recovery flash controller
    let mux_recovery_flash =
        components::flash::FlashMuxComponent::new(&peripherals.recovery_flash_ctrl).finalize(
            components::flash_mux_component_static!(flash_driver::flash_ctrl::EmulatedFlashCtrl),
        );

    // Instantiate a flashUser for recovery image partition driver
    let recovery_image_par_fl_user = components::flash::FlashUserComponent::new(mux_recovery_flash)
        .finalize(components::flash_user_component_static!(
            flash_driver::flash_ctrl::EmulatedFlashCtrl
        ));

    let recovery_image_par = runtime_components::flash_partition::FlashPartitionComponent::new(
        board_kernel,
        capsules_runtime::flash_partition::RECOVERY_IMAGE_PAR_DRIVER_NUM, // Driver number
        recovery_image_par_fl_user,
        0x0,        // Start address of the partition. Place holder for testing
        0x200_0000, // Length of the partition. Place holder for testing
    )
    .finalize(crate::flash_partition_component_static!(
        virtual_flash::FlashUser<'static, flash_driver::flash_ctrl::EmulatedFlashCtrl>,
        capsules_runtime::flash_partition::BUF_LEN
    ));

    // Need to enable all interrupts for Tock Kernel
    chip.enable_pic_interrupts();
    chip.enable_timer_interrupts();

    // enable interrupts globally
    csr::CSR
        .mie
        .modify(csr::mie::mie::mext::SET + csr::mie::mie::msoft::SET + csr::mie::mie::BIT29::SET);
    csr::CSR.mstatus.modify(csr::mstatus::mstatus::mie::SET);

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
            active_image_par,
            recovery_image_par,
        }
    );

    kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            core::ptr::addr_of!(_sapps),
            core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
        ),
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(_sappmem),
            core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
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
        crate::tests::i3c_target_test::test_i3c_simple()
    } else if cfg!(feature = "test-i3c-constant-writes") {
        debug!("Executing test-i3c-constant-writes");
        crate::tests::i3c_target_test::test_i3c_constant_writes()
    } else if cfg!(feature = "test-flash-ctrl-init") {
        debug!("Executing test-flash-ctrl-init");
        crate::tests::flash_ctrl_test::test_flash_ctrl_init()
    } else if cfg!(feature = "test-flash-ctrl-read-write-page") {
        debug!("Executing test-flash-ctrl-read-write-page");
        crate::tests::flash_ctrl_test::test_flash_ctrl_read_write_page()
    } else if cfg!(feature = "test-flash-ctrl-erase-page") {
        debug!("Executing test-flash-ctrl-erase-page");
        crate::tests::flash_ctrl_test::test_flash_ctrl_erase_page()
    } else if cfg!(feature = "test-flash-storage-read-write") {
        debug!("Executing test-flash-storage-read-write");
        crate::tests::flash_storage_test::test_flash_storage_read_write()
    } else if cfg!(feature = "test-flash-storage-erase") {
        debug!("Executing test-flash-storage-erase");
        crate::tests::flash_storage_test::test_flash_storage_erase()
    } else {
        None
    };

    #[cfg(feature = "test-mctp-capsule-loopback")]
    {
        debug!("Executing test-mctp-capsule-loopback");
        crate::tests::mctp_test::test_mctp_capsule_loopback(mux_mctp);
    }

    if let Some(exit) = exit {
        crate::io::exit_emulator(exit);
    }
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
