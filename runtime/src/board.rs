// Licensed under the Apache-2.0 license

use crate::chip::VeeRDefaultPeripherals;
use crate::chip::TIMERS;
use crate::components as runtime_components;
use crate::timers::InternalTimers;

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
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
    feature = "test-flash-ctrl-erase-page"
))]
static mut BOARD: Option<&'static kernel::Kernel> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page"
))]
static mut PLATFORM: Option<&'static VeeR> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page"
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
    mctp_pldm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_vendor_def_pci: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
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
            capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM => f(Some(self.mctp_pldm)),
            capsules_runtime::mctp::driver::MCTP_VENDOR_DEFINED_PCI_DRIVER_NUM => {
                f(Some(self.mctp_vendor_def_pci))
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

/// Main function called after RAM initialized.
///
/// # Safety
/// Accesses memory, memory-mapped registers and CSRs.
pub unsafe fn main() {
    // only machine mode
    rv32i::configure_trap_handler();

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
        VeeRDefaultPeripherals::new(&*mux_alarm)
    );

    let chip = static_init!(VeeRChip, crate::chip::VeeR::new(peripherals));
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

    let mctp_mux = runtime_components::mctp_mux::MCTPMuxComponent::new(&peripherals.i3c)
        .finalize(crate::mctp_mux_component_static!(MCTPI3CBinding));

    let mctp_spdm_msg_types = static_init!(
        [u8; 2],
        [
            capsules_runtime::mctp::base_protocol::MessageType::Spdm,
            capsules_runtime::mctp::base_protocol::MessageType::SecureSpdm,
        ]
    );
    let mctp_spdm = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM,
        mctp_mux,
        mctp_spdm_msg_types,
    )
    .finalize(crate::mctp_driver_component_static!());

    let mctp_pldm_msg_types = static_init!(
        [u8; 1],
        [capsules_runtime::mctp::base_protocol::MessageType::Pldm as u8]
    );
    let mctp_pldm = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM,
        mctp_mux,
        mctp_pldm_msg_types,
    )
    .finalize(crate::mctp_driver_component_static!());

    let mctp_vendor_def_pci_msg_types = static_init!(
        [capsules_runtime::mctp::base_protocol::MessageType; 1],
        [capsules_runtime::mctp::base_protocol::MessageType::VendorDefinedPci]
    );
    let mctp_vendor_def_pci = runtime_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_VENDOR_DEFINED_PCI_DRIVER_NUM,
        mctp_mux,
        mctp_vendor_def_pci_msg_types,
    )
    .finalize(crate::mctp_driver_component_static!());

    peripherals.init();

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
            mctp_pldm,
            mctp_vendor_def_pci,
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
        feature = "test-flash-ctrl-erase-page"
    ))]
    {
        PLATFORM = Some(veer);
        MAIN_CAP = Some(&create_capability!(capabilities::MainLoopCapability));
        BOARD = Some(board_kernel);
    }

    // Run any requested test
    let exit = if cfg!(feature = "test-i3c-simple") {
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
    } else if cfg!(feature = "test-mctp-send-loopback") {
        debug!("Executing test-mctp-send-loopback");
        crate::tests::mctp_test::test_mctp_send_loopback(mctp_mux)
    } else {
        None
    };
    if let Some(exit) = exit {
        crate::io::exit_emulator(exit);
    }
    board_kernel.kernel_loop(veer, chip, None::<&kernel::ipc::IPC<0>>, &main_loop_cap);
}

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page"
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
