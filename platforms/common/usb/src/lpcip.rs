// Licensed under the Apache-2.0 license

//! NXP LPCIP3511 initialization and EP0 enumeration.
//!
//! FPGA hub bring-up can enumerate Device 0 first, then connect and enumerate
//! Device 1 as an EP0-only vendor-specific test device.
//!
//! With `usb-recovery`, Device 0 standard EP0 service persists through recovery
//! boot while Device 1 stays disabled. OCP framing and image ingress remain
//! hardware-owned, rather than using the software [`UsbDeviceDriver`] command
//! path. The separate `usb-compliance` mode services both devices without OCP.

use caliptra_mcu_ocp::usb::descriptors::*;
use caliptra_mcu_ocp::usb::setup::{SetupPacket, StandardRequest, SETUP_PACKET_LEN};
use caliptra_mcu_registers_generated::{usb_combo, usb_dev0_mem, usb_dev1, usb_dev1_mem};
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};
use zerocopy::IntoBytes;

#[cfg(any(feature = "usb-compliance", feature = "usb-recovery"))]
mod compliance;
#[cfg(feature = "usb-recovery")]
pub use compliance::UsbRecovery;

const MAX_TRANSFER_SIZE: u16 = 64;

const EP0_OUT_DESCRIPTOR: usize = 0;
const SETUP_DESCRIPTOR: usize = 1;
const EP0_IN_DESCRIPTOR: usize = 2;
const FIRST_GENERIC_DESCRIPTOR: usize = 4;
const DESCRIPTOR_COUNT: usize = 64;

const SETUP_BUFFER_OFFSET: usize = 0x100;
const OUT_BUFFER_OFFSET: usize = 0x140;
const IN_BUFFER_OFFSET: usize = 0x180;

const BUFFER_OFFSET_MASK: u32 = 0x7ff;
const NBYTES_SHIFT: u32 = 11;
const STALL: u32 = 1 << 29;
const DISABLED: u32 = 1 << 30;
const ACTIVE: u32 = 1 << 31;
const IMPLEMENTED_INTERRUPTS: u32 = 0xc000_ffff;
const DEFAULT_ULPI_POLL_LIMIT: u32 = 1_000_000;
const KEEP_PHY_CLOCK: u32 = usb_combo::bits::DevcmdstatT::ForceNeedclk::SET.value;

// Test-only identity; Device 1 does not advertise OCP recovery functionality.
const DEVICE1_DESCRIPTOR: DeviceDescriptor =
    DeviceDescriptor::ocp(0x0200, 0x0000, 0x0001, 0x0100, 0, 0, 0);
const DEVICE1_CONFIGURATION: [u8; 18] = [
    9, 2, 18, 0, 1, 1, 0, 0xc0, 0, // Self-powered configuration, one interface.
    9, 4, 0, 0, 0, 0xff, 0, 0, 0, // Vendor-specific interface, EP0 only.
];
const DEVICE1_QUALIFIER: [u8; 10] = [10, 6, 0, 2, 0, 0, 0, 64, 1, 0];

#[derive(Clone, Copy)]
enum DeviceController {
    Device0 {
        regs: StaticRef<usb_combo::regs::UsbCombo>,
        memory: StaticRef<usb_dev0_mem::regs::UsbDev0Mem>,
    },
    Device1 {
        regs: StaticRef<usb_dev1::regs::UsbDev1>,
        memory: StaticRef<usb_dev1_mem::regs::UsbDev1Mem>,
    },
}

impl DeviceController {
    fn number(&self) -> u8 {
        match self {
            Self::Device0 { .. } => 0,
            Self::Device1 { .. } => 1,
        }
    }

    // Both controllers implement the same DEVCMDSTAT and interrupt bit layout.
    fn command_status(&self) -> u32 {
        match self {
            Self::Device0 { regs, .. } => regs.dev0_csr_devcmdstat.get(),
            Self::Device1 { regs, .. } => regs.devcmdstat.get(),
        }
    }

    fn set_command_status(&self, value: u32) {
        match self {
            Self::Device0 { regs, .. } => regs.dev0_csr_devcmdstat.set(value),
            Self::Device1 { regs, .. } => regs.devcmdstat.set(value),
        }
    }

    fn set_interrupt_enable(&self, value: u32) {
        match self {
            Self::Device0 { regs, .. } => regs.dev0_csr_inten.set(value),
            Self::Device1 { regs, .. } => regs.inten.set(value),
        }
    }

    fn clear_interrupts(&self, value: u32) {
        match self {
            Self::Device0 { regs, .. } => regs.dev0_csr_intstat.set(value),
            Self::Device1 { regs, .. } => regs.intstat.set(value),
        }
    }

    fn initialize(&self) {
        self.set_command_status(KEEP_PHY_CLOCK);
        self.set_interrupt_enable(0);
        self.clear_interrupts(IMPLEMENTED_INTERRUPTS);
        match self {
            Self::Device0 { regs, .. } => {
                regs.dev0_csr_epliststart.set(0);
                regs.dev0_csr_databufstart.set(0);
            }
            Self::Device1 { regs, .. } => {
                regs.epliststart.set(0);
                regs.databufstart.set(0);
            }
        }
    }

    fn read_memory_word(&self, index: usize) -> u32 {
        match self {
            Self::Device0 { memory, .. } => memory.usb_dev0_mem[index].get(),
            Self::Device1 { memory, .. } => memory.usb_dev1_mem[index].get(),
        }
    }

    fn write_memory_word(&self, index: usize, value: u32) {
        match self {
            Self::Device0 { memory, .. } => memory.usb_dev0_mem[index].set(value),
            Self::Device1 { memory, .. } => memory.usb_dev1_mem[index].set(value),
        }
    }
}

const USB3320_VENDOR_ID: [u8; 2] = [0x24, 0x04];
const USB3320_PRODUCT_ID: [u8; 2] = [0x07, 0x00];
const USB3320_FUNCTION_CTRL: u8 = 0x04;
const USB3320_OTG_CTRL: u8 = 0x0a;
const USB3320_SCRATCH: u8 = 0x16;
const USB3320_SCRATCH_SET: u8 = 0x17;
const USB3320_SCRATCH_CLEAR: u8 = 0x18;
const USB3320_HS_DEVICE_FUNCTION_CTRL: u8 = 0x40;
const PHY_IDENTITY_DIAGNOSTIC_RETRIES: u32 = 3;
const PHY_IDENTITY_DIAGNOSTIC_DELAY: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LpcipUsbError {
    RecoveryReset,
    RecoveryDisconnected,
    RecoverySuspended,
    CancellationTimeout,
    Timeout,
    UnsupportedPhy,
    PhyIdentityMismatch,
    PhyScratchMismatch,
}

pub struct LpcipUsbDriver {
    regs: StaticRef<usb_combo::regs::UsbCombo>,
    controller: DeviceController,
    poll_limit: Option<u32>,
}

impl LpcipUsbDriver {
    pub const fn new(
        regs: StaticRef<usb_combo::regs::UsbCombo>,
        memory: StaticRef<usb_dev0_mem::regs::UsbDev0Mem>,
    ) -> Self {
        Self {
            regs,
            controller: DeviceController::Device0 { regs, memory },
            poll_limit: None,
        }
    }

    pub const fn with_poll_limit(mut self, poll_limit: u32) -> Self {
        self.poll_limit = Some(poll_limit);
        self
    }

    /// Enumerate Device 0 before connecting Device 1 on the second hub port.
    ///
    /// Device 1 must be accessible to the MCU. Its descriptors are for hub
    /// testing only, not a second OCP recovery interface. The shared PHY and
    /// hub are initialized only once; Device 0 stays connected throughout.
    pub fn init_and_enumerate_with_device1(
        &mut self,
        regs: StaticRef<usb_dev1::regs::UsbDev1>,
        memory: StaticRef<usb_dev1_mem::regs::UsbDev1Mem>,
    ) -> Result<(), LpcipUsbError> {
        let controller = DeviceController::Device1 { regs, memory };
        caliptra_mcu_romtime::println!(
            "[usb] Keeping Device 1 disabled until Device 0 is configured"
        );
        controller.set_command_status(KEEP_PHY_CLOCK);
        controller.set_interrupt_enable(0);
        self.init_and_enumerate()?;

        let device1 = Self {
            regs: self.regs,
            controller,
            poll_limit: self.poll_limit,
        };
        caliptra_mcu_romtime::println!("[usb] Initializing Device 1");
        device1.initialize_endpoints();
        device1.enable_interrupts();
        caliptra_mcu_romtime::println!("[usb] Connecting Device 1");
        device1.connect();
        device1.enumerate()
    }

    /// Print the Device 0 controller registers and readable USB3320 registers.
    pub fn dump_registers(&self) {
        caliptra_mcu_romtime::println!("[usb] LPCIP Device 0 registers:");
        caliptra_mcu_romtime::println!(
            "[usb]   DEVCMDSTAT   = 0x{:08x}",
            self.regs.dev0_csr_devcmdstat.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   INFO         = 0x{:08x}",
            self.regs.dev0_csr_info.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   EPLISTSTART  = 0x{:08x}",
            self.regs.dev0_csr_epliststart.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   DATABUFSTART = 0x{:08x}",
            self.regs.dev0_csr_databufstart.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   LPM          = 0x{:08x}",
            self.regs.dev0_csr_lpm.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   EPSKIP       = 0x{:08x}",
            self.regs.dev0_csr_epskip.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   EPINUSE      = 0x{:08x}",
            self.regs.dev0_csr_epinuse.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   EPBUFCFG     = 0x{:08x}",
            self.regs.dev0_csr_epbufcfg.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   INTSTAT      = 0x{:08x}",
            self.regs.dev0_csr_intstat.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   INTEN        = 0x{:08x}",
            self.regs.dev0_csr_inten.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   INTSETSTAT   = 0x{:08x}",
            self.regs.dev0_csr_intsetstat.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   INTROUTE     = 0x{:08x}",
            self.regs.dev0_csr_introute.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   CONFIG       = 0x{:08x}",
            self.regs.dev0_csr_config.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   EPTOGGLE     = 0x{:08x}",
            self.regs.dev0_csr_eptoggle.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   HUB_CONTROL  = 0x{:08x}",
            self.regs.hub_control.get()
        );
        caliptra_mcu_romtime::println!(
            "[usb]   ULPIDEBUG    = 0x{:08x}",
            self.regs.hub_ulpidebug.get()
        );

        caliptra_mcu_romtime::println!("[usb] USB3320 registers:");
        for (name, address) in [
            ("VENDOR_ID_LOW  ", 0x00),
            ("VENDOR_ID_HIGH ", 0x01),
            ("PRODUCT_ID_LOW ", 0x02),
            ("PRODUCT_ID_HIGH", 0x03),
            ("FUNCTION_CTRL  ", 0x04),
            ("INTERFACE_CTRL ", 0x07),
            ("OTG_CTRL       ", 0x0a),
            ("USB_INT_EN_RISE", 0x0d),
            ("USB_INT_EN_FALL", 0x10),
            ("USB_INT_STATUS ", 0x13),
            ("USB_INT_LATCH  ", 0x14),
            ("DEBUG          ", 0x15),
            ("SCRATCH        ", 0x16),
        ] {
            match self.ulpi_read(address) {
                Ok(value) => caliptra_mcu_romtime::println!(
                    "[usb]   {} [0x{:02x}] = 0x{:02x}",
                    name,
                    address,
                    value
                ),
                Err(error) => {
                    caliptra_mcu_romtime::println!(
                        "[usb]   ULPI read failed at 0x{:02x}: {:?}",
                        address,
                        error
                    );
                    break;
                }
            }
        }
    }

    /// Initialize Device 0 and service standard EP0 requests until configured.
    ///
    /// The platform must enable and release reset for the external USB PHY and
    /// controller clock before calling this method.
    pub fn init_and_enumerate(&mut self) -> Result<(), LpcipUsbError> {
        caliptra_mcu_romtime::println!("[usb] Disconnecting and initializing Device 0");
        self.disconnect_and_initialize();
        caliptra_mcu_romtime::println!("[usb] Initializing USB3320 PHY");
        self.initialize_phy()?;
        caliptra_mcu_romtime::println!("[usb] Waiting for VBUS");
        self.wait_for_vbus()?;
        caliptra_mcu_romtime::println!("[usb] Enabling Device 0 interrupts");
        self.enable_interrupts();
        caliptra_mcu_romtime::println!("[usb] Connecting Device 0");
        self.connect();
        self.enumerate()
    }

    fn enumerate(&self) -> Result<(), LpcipUsbError> {
        let device = self.controller.number();
        caliptra_mcu_romtime::println!("[usb] Device {}: waiting for USB bus reset", device);
        self.wait_for_bus_reset()?;
        caliptra_mcu_romtime::println!(
            "[usb] Device {}: servicing EP0 enumeration requests",
            device
        );

        loop {
            self.wait_for_setup()?;
            let setup = self.read_setup();
            let raw = setup.as_bytes();
            caliptra_mcu_romtime::println!(
                "[usb] Device {} SETUP {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                device,
                raw[0],
                raw[1],
                raw[2],
                raw[3],
                raw[4],
                raw[5],
                raw[6],
                raw[7]
            );
            self.clear_setup_received();

            match setup.standard_request() {
                Some(StandardRequest::GetDescriptor) => {
                    self.send_descriptor(&setup)?;
                }
                Some(StandardRequest::SetAddress) => self.set_address(&setup)?,
                Some(StandardRequest::SetConfiguration) => {
                    if setup.w_value != [1, 0] {
                        self.stall_ep0();
                        continue;
                    }
                    self.send_zlp_in()?;
                    caliptra_mcu_romtime::println!(
                        "[usb] EP0 enumeration complete (Device {})",
                        device
                    );
                    return Ok(());
                }
                Some(StandardRequest::GetConfiguration) => {
                    self.send_control_read(&[0], setup.data_length() as usize)?;
                }
                Some(StandardRequest::GetStatus) => {
                    self.send_control_read(&[1, 0], setup.data_length() as usize)?;
                }
                _ => {
                    self.stall_ep0();
                }
            }
        }
    }

    /// Run the FPGA bring-up register test through the LPCIP ULPIDEBUG gateway.
    pub fn run_ulpi_debug_test(&self) -> Result<(), LpcipUsbError> {
        const SCRATCH_PATTERNS: [u8; 12] = [
            0x00, 0xff, 0xa5, 0x5a, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        ];

        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Initial state: DEVCMDSTAT=0x{:08x} CONFIG=0x{:08x} ULPIDEBUG=0x{:08x}",
            self.regs.dev0_csr_devcmdstat.get(),
            self.regs.dev0_csr_config.get(),
            self.regs.hub_ulpidebug.get()
        );
        if !self
            .regs
            .dev0_csr_config
            .is_set(usb_combo::bits::ConfigT::Ulpi)
        {
            caliptra_mcu_romtime::println!(
                "[usb-ulpi-test] Controller does not advertise ULPI support"
            );
            return Err(LpcipUsbError::UnsupportedPhy);
        }

        self.regs.dev0_csr_devcmdstat.set(KEEP_PHY_CLOCK);
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Forced PHY clock: DEVCMDSTAT=0x{:08x}",
            self.regs.dev0_csr_devcmdstat.get()
        );
        self.regs
            .hub_ulpidebug
            .write(usb_combo::bits::UlpidebugT::PhyMode::SET);
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Selected ULPI mode: ULPIDEBUG=0x{:08x}",
            self.regs.hub_ulpidebug.get()
        );

        caliptra_mcu_romtime::println!("[usb-ulpi-test] Reading USB3320 identity");
        let vendor_id = [
            self.ulpi_debug_test_read(0x00)?,
            self.ulpi_debug_test_read(0x01)?,
        ];
        let product_id = [
            self.ulpi_debug_test_read(0x02)?,
            self.ulpi_debug_test_read(0x03)?,
        ];
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Vendor ID: 0x{:02x}{:02x}",
            vendor_id[1],
            vendor_id[0]
        );
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Product ID: 0x{:02x}{:02x}",
            product_id[1],
            product_id[0]
        );
        if vendor_id != USB3320_VENDOR_ID || product_id != USB3320_PRODUCT_ID {
            caliptra_mcu_romtime::println!(
                "[usb-ulpi-test] Identity mismatch: expected vendor=0x0424 product=0x0007"
            );
            return Err(LpcipUsbError::PhyIdentityMismatch);
        }

        caliptra_mcu_romtime::println!("[usb-ulpi-test] Reading original scratch value");
        let original_scratch = self.ulpi_debug_test_read(USB3320_SCRATCH)?;
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Original scratch: 0x{:02x}",
            original_scratch
        );

        let test_result: Result<(), LpcipUsbError> = (|| {
            for pattern in SCRATCH_PATTERNS {
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] Testing scratch pattern 0x{:02x}",
                    pattern
                );
                self.ulpi_debug_test_write(USB3320_SCRATCH, pattern)?;
                let actual = self.ulpi_debug_test_read(USB3320_SCRATCH)?;
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] Scratch write=0x{:02x} read=0x{:02x}",
                    pattern,
                    actual
                );
                if actual != pattern {
                    caliptra_mcu_romtime::println!(
                        "[usb-ulpi-test] Scratch mismatch at pattern 0x{:02x}",
                        pattern
                    );
                    return Err(LpcipUsbError::PhyScratchMismatch);
                }
            }
            Ok(())
        })();

        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] Restoring scratch to 0x{:02x}",
            original_scratch
        );
        let restore_result = self.ulpi_debug_test_write(USB3320_SCRATCH, original_scratch);
        test_result?;
        restore_result?;

        caliptra_mcu_romtime::println!("[usb-ulpi-test] PASS");
        Ok(())
    }

    fn ulpi_debug_test_read(&self, address: u8) -> Result<u8, LpcipUsbError> {
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] READ  addr=0x{:02x} before=0x{:08x}",
            address,
            self.regs.hub_ulpidebug.get()
        );
        match self.ulpi_read(address) {
            Ok(value) => {
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] READ  addr=0x{:02x} value=0x{:02x} after=0x{:08x}",
                    address,
                    value,
                    self.regs.hub_ulpidebug.get()
                );
                Ok(value)
            }
            Err(error) => {
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] READ  addr=0x{:02x} failed={:?} pending=0x{:08x}",
                    address,
                    error,
                    self.regs.hub_ulpidebug.get()
                );
                Err(error)
            }
        }
    }

    fn ulpi_debug_test_write(&self, address: u8, value: u8) -> Result<(), LpcipUsbError> {
        caliptra_mcu_romtime::println!(
            "[usb-ulpi-test] WRITE addr=0x{:02x} value=0x{:02x} before=0x{:08x}",
            address,
            value,
            self.regs.hub_ulpidebug.get()
        );
        match self.ulpi_write(address, value) {
            Ok(()) => {
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] WRITE addr=0x{:02x} value=0x{:02x} after=0x{:08x}",
                    address,
                    value,
                    self.regs.hub_ulpidebug.get()
                );
                Ok(())
            }
            Err(error) => {
                caliptra_mcu_romtime::println!(
                    "[usb-ulpi-test] WRITE addr=0x{:02x} value=0x{:02x} failed={:?} pending=0x{:08x}",
                    address,
                    value,
                    error,
                    self.regs.hub_ulpidebug.get()
                );
                Err(error)
            }
        }
    }

    fn initialize_phy(&self) -> Result<(), LpcipUsbError> {
        if !self
            .regs
            .dev0_csr_config
            .is_set(usb_combo::bits::ConfigT::Ulpi)
        {
            return Err(LpcipUsbError::UnsupportedPhy);
        }

        caliptra_mcu_romtime::println!(
            "[usb-phy] CONFIG=0x{:08x} ULPIDEBUG=0x{:08x} HUB_CONTROL=0x{:08x} DEVCMDSTAT=0x{:08x}",
            self.regs.dev0_csr_config.get(),
            self.regs.hub_ulpidebug.get(),
            self.regs.hub_control.get(),
            self.controller.command_status()
        );

        self.regs
            .hub_ulpidebug
            .write(usb_combo::bits::UlpidebugT::PhyMode::SET);

        //        self.verify_phy_scratch()?;

        let (vendor_id, product_id) = self.read_phy_identity()?;
        if vendor_id != USB3320_VENDOR_ID || product_id != USB3320_PRODUCT_ID {
            caliptra_mcu_romtime::println!(
                "[usb-phy] Identity mismatch: read vendor=0x{:02x}{:02x} product=0x{:02x}{:02x}, expected vendor=0x0424 product=0x0007",
                vendor_id[1],
                vendor_id[0],
                product_id[1],
                product_id[0]
            );
            // Diagnostic only: show whether the PHY settles later. Still fail.
            for attempt in 1..=PHY_IDENTITY_DIAGNOSTIC_RETRIES {
                for _ in 0..PHY_IDENTITY_DIAGNOSTIC_DELAY {
                    core::hint::spin_loop();
                }
                match self.read_phy_identity() {
                    Ok((vendor, product)) => caliptra_mcu_romtime::println!(
                        "[usb-phy] Re-read {}: vendor=0x{:02x}{:02x} product=0x{:02x}{:02x}",
                        attempt,
                        vendor[1],
                        vendor[0],
                        product[1],
                        product[0]
                    ),
                    Err(error) => {
                        caliptra_mcu_romtime::println!(
                            "[usb-phy] Re-read {} failed: {:?}",
                            attempt,
                            error
                        )
                    }
                }
            }
            return Err(LpcipUsbError::PhyIdentityMismatch);
        }
        caliptra_mcu_romtime::println!("[usb-phy] USB3320 identity OK");

        self.ulpi_write(USB3320_FUNCTION_CTRL, USB3320_HS_DEVICE_FUNCTION_CTRL)?;
        self.ulpi_write(USB3320_OTG_CTRL, 0)?;
        Ok(())
    }

    fn read_phy_identity(&self) -> Result<([u8; 2], [u8; 2]), LpcipUsbError> {
        let mut id = [0u8; 4];
        for (address, byte) in id.iter_mut().enumerate() {
            *byte = self.ulpi_read(address as u8).inspect_err(|error| {
                caliptra_mcu_romtime::println!(
                    "[usb-phy] ULPI read 0x{:02x} failed: {:?} ULPIDEBUG=0x{:08x}",
                    address,
                    error,
                    self.regs.hub_ulpidebug.get()
                )
            })?;
            caliptra_mcu_romtime::println!(
                "[usb-phy] ULPI read 0x{:02x} = 0x{:02x} ULPIDEBUG=0x{:08x}",
                address,
                *byte,
                self.regs.hub_ulpidebug.get()
            );
        }
        Ok(([id[0], id[1]], [id[2], id[3]]))
    }

    fn verify_phy_scratch(&self) -> Result<(), LpcipUsbError> {
        self.ulpi_write(USB3320_SCRATCH, 0xa5)?;
        if self.ulpi_read(USB3320_SCRATCH)? != 0xa5 {
            return Err(LpcipUsbError::PhyScratchMismatch);
        }

        self.ulpi_write(USB3320_SCRATCH_SET, 0x0f)?;
        if self.ulpi_read(USB3320_SCRATCH)? != 0xaf {
            return Err(LpcipUsbError::PhyScratchMismatch);
        }

        self.ulpi_write(USB3320_SCRATCH_CLEAR, 0xf0)?;
        if self.ulpi_read(USB3320_SCRATCH)? != 0x0f {
            return Err(LpcipUsbError::PhyScratchMismatch);
        }
        Ok(())
    }

    fn ulpi_read(&self, address: u8) -> Result<u8, LpcipUsbError> {
        let transaction = Self::ulpi_transaction(address);
        self.regs.hub_ulpidebug.set(transaction);
        self.regs
            .hub_ulpidebug
            .set(transaction | usb_combo::bits::UlpidebugT::PhyAccess::SET.value);
        self.wait_for_ulpi_access()?;
        Ok(self
            .regs
            .hub_ulpidebug
            .read(usb_combo::bits::UlpidebugT::PhyRdata) as u8)
    }

    fn ulpi_write(&self, address: u8, value: u8) -> Result<(), LpcipUsbError> {
        let transaction = Self::ulpi_transaction(address)
            | usb_combo::bits::UlpidebugT::PhyWdata
                .val(u32::from(value))
                .value
            | usb_combo::bits::UlpidebugT::PhyRw::SET.value;
        self.regs.hub_ulpidebug.set(transaction);
        self.regs
            .hub_ulpidebug
            .set(transaction | usb_combo::bits::UlpidebugT::PhyAccess::SET.value);
        self.wait_for_ulpi_access()
    }

    fn ulpi_transaction(address: u8) -> u32 {
        usb_combo::bits::UlpidebugT::PhyMode::SET.value
            | usb_combo::bits::UlpidebugT::PhyAddr
                .val(u32::from(address & 0x0f))
                .value
            | usb_combo::bits::UlpidebugT::PhyAddrHigh
                .val(u32::from(address >> 4))
                .value
    }

    fn wait_for_ulpi_access(&self) -> Result<(), LpcipUsbError> {
        let poll_limit = self.poll_limit.unwrap_or(DEFAULT_ULPI_POLL_LIMIT);
        for _ in 0..poll_limit {
            if !self
                .regs
                .hub_ulpidebug
                .is_set(usb_combo::bits::UlpidebugT::PhyAccess)
            {
                return Ok(());
            }
        }
        Err(LpcipUsbError::Timeout)
    }

    fn disconnect_and_initialize(&self) {
        self.regs.hub_control.set(1);
        self.initialize_endpoints();
    }

    fn initialize_endpoints(&self) {
        self.controller.initialize();
        for descriptor in 0..DESCRIPTOR_COUNT {
            self.write_memory_word(descriptor, 0);
        }
        self.write_memory_word(SETUP_DESCRIPTOR, Self::buffer_offset(SETUP_BUFFER_OFFSET));
        for descriptor in FIRST_GENERIC_DESCRIPTOR..DESCRIPTOR_COUNT {
            self.write_memory_word(descriptor, DISABLED);
        }
    }

    fn wait_for_vbus(&self) -> Result<(), LpcipUsbError> {
        self.wait_until(|| {
            self.regs
                .dev0_csr_devcmdstat
                .is_set(usb_combo::bits::DevcmdstatT::VbusDebounced)
        })
    }

    fn enable_interrupts(&self) {
        self.controller.set_interrupt_enable(
            usb_combo::bits::IntenT::EpIntEn.val(0x3).value
                | usb_combo::bits::IntenT::DevIntEn::SET.value,
        );
        self.controller.clear_interrupts(IMPLEMENTED_INTERRUPTS);
    }

    fn connect(&self) {
        if matches!(self.controller, DeviceController::Device0 { .. }) {
            self.regs.hub_control.set(
                usb_combo::bits::Control::Enable::SET.value
                    | usb_combo::bits::Control::Dcon::SET.value,
            );
        }
        self.controller.set_command_status(
            KEEP_PHY_CLOCK
                | usb_combo::bits::DevcmdstatT::DevEn::SET.value
                | usb_combo::bits::DevcmdstatT::Dcon::SET.value,
        );
    }

    fn wait_for_bus_reset(&self) -> Result<(), LpcipUsbError> {
        self.wait_until(|| {
            self.controller.command_status() & usb_combo::bits::DevcmdstatT::DresC::SET.value != 0
        })?;
        self.controller.set_command_status(
            KEEP_PHY_CLOCK
                | usb_combo::bits::DevcmdstatT::DevEn::SET.value
                | usb_combo::bits::DevcmdstatT::Dcon::SET.value
                | usb_combo::bits::DevcmdstatT::DresC::SET.value,
        );
        self.controller
            .clear_interrupts(usb_combo::bits::IntstatT::DevInt::SET.value);
        Ok(())
    }

    fn wait_for_setup(&self) -> Result<(), LpcipUsbError> {
        self.wait_until(|| {
            self.controller.command_status() & usb_combo::bits::DevcmdstatT::Setup::SET.value != 0
        })
    }

    fn clear_setup_received(&self) {
        let value =
            self.controller.command_status() | usb_combo::bits::DevcmdstatT::Setup::SET.value;
        self.controller.set_command_status(value);
        self.clear_endpoint_interrupt(EP0_OUT_DESCRIPTOR);
    }

    fn read_setup(&self) -> SetupPacket {
        let first = self.read_memory_word(SETUP_BUFFER_OFFSET / 4).to_le_bytes();
        let second = self
            .read_memory_word(SETUP_BUFFER_OFFSET / 4 + 1)
            .to_le_bytes();
        let raw: [u8; SETUP_PACKET_LEN] = [
            first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
        ];
        zerocopy::transmute!(raw)
    }

    fn send_descriptor(&self, setup: &SetupPacket) -> Result<(), LpcipUsbError> {
        if matches!(self.controller, DeviceController::Device1 { .. }) {
            let requested = setup.data_length() as usize;
            if setup.descriptor_index() != 0 {
                self.stall_ep0();
                return Ok(());
            }
            return match setup.w_value[1] {
                1 => self.send_control_read(DEVICE1_DESCRIPTOR.as_bytes(), requested),
                2 => self.send_control_read(&DEVICE1_CONFIGURATION, requested),
                6 => self.send_control_read(&DEVICE1_QUALIFIER, requested),
                7 => {
                    let mut descriptor = DEVICE1_CONFIGURATION;
                    descriptor[1] = 7;
                    self.send_control_read(&descriptor, requested)
                }
                _ => {
                    self.stall_ep0();
                    Ok(())
                }
            };
        }
        match setup.descriptor_type() {
            Some(DescriptorType::Device) => {
                let descriptor = DeviceDescriptor::ocp(0x0200, 0x0424, 0x0007, 0x0100, 0, 0, 0);
                self.send_control_read(descriptor.as_bytes(), setup.data_length() as usize)
            }
            Some(DescriptorType::Configuration) => {
                let descriptor = ConfigurationTree::ocp(
                    BmAttributes::new(true, false),
                    MaxPower2mA(50),
                    None,
                    MAX_TRANSFER_SIZE,
                    MAX_TRANSFER_SIZE,
                );
                self.send_control_read(descriptor.as_bytes(), setup.data_length() as usize)
            }
            Some(DescriptorType::String) if setup.descriptor_index() == 0 => {
                let descriptor = StringDescriptorZero::ocp();
                self.send_control_read(descriptor.as_bytes(), setup.data_length() as usize)
            }
            Some(DescriptorType::String)
                if setup.descriptor_index() == OCP_INTERFACE_STRING_INDEX =>
            {
                let descriptor = OcpInterfaceStringDescriptor::ocp();
                self.send_control_read(descriptor.as_bytes(), setup.data_length() as usize)
            }
            _ => {
                self.stall_ep0();
                Ok(())
            }
        }
    }

    fn set_address(&self, setup: &SetupPacket) -> Result<(), LpcipUsbError> {
        let address = u32::from(setup.w_value[0] & 0x7f);
        let value = self.controller.command_status() & !usb_combo::bits::DevcmdstatT::DevAddr.mask;
        self.controller
            .set_command_status(value | usb_combo::bits::DevcmdstatT::DevAddr.val(address).value);
        self.send_zlp_in()
    }

    fn send_control_read(&self, data: &[u8], requested: usize) -> Result<(), LpcipUsbError> {
        let length = core::cmp::min(data.len(), requested);
        self.write_buffer(IN_BUFFER_OFFSET, &data[..length]);
        //        caliptra_mcu_romtime::println!("[usb] EP0 IN data arm: {} bytes", length);
        self.arm_in(length);
        self.wait_descriptor_inactive(EP0_IN_DESCRIPTOR)?;
        //        caliptra_mcu_romtime::println!("[usb] EP0 IN data complete");
        //        caliptra_mcu_romtime::println!("[usb] EP0 OUT status arm");
        self.arm_out(MAX_TRANSFER_SIZE.into());
        self.wait_descriptor_inactive(EP0_OUT_DESCRIPTOR)?;
        //        caliptra_mcu_romtime::println!("[usb] EP0 OUT status complete");
        Ok(())
    }

    fn send_zlp_in(&self) -> Result<(), LpcipUsbError> {
        //        caliptra_mcu_romtime::println!("[usb] EP0 IN status arm");
        self.arm_in(0);
        self.wait_descriptor_inactive(EP0_IN_DESCRIPTOR)?;
        //        caliptra_mcu_romtime::println!("[usb] EP0 IN status complete");
        Ok(())
    }

    fn arm_out(&self, length: usize) {
        self.write_memory_word(
            EP0_OUT_DESCRIPTOR,
            Self::buffer_descriptor(OUT_BUFFER_OFFSET, length) | ACTIVE,
        );
    }

    fn arm_in(&self, length: usize) {
        self.write_memory_word(
            EP0_IN_DESCRIPTOR,
            Self::buffer_descriptor(IN_BUFFER_OFFSET, length) | ACTIVE,
        );
    }

    fn stall_ep0(&self) {
        self.write_memory_word(
            EP0_OUT_DESCRIPTOR,
            Self::buffer_descriptor(OUT_BUFFER_OFFSET, 0) | STALL,
        );
        self.write_memory_word(
            EP0_IN_DESCRIPTOR,
            Self::buffer_descriptor(IN_BUFFER_OFFSET, 0) | STALL,
        );
    }

    fn wait_descriptor_inactive(&self, descriptor: usize) -> Result<(), LpcipUsbError> {
        self.wait_until(|| self.read_memory_word(descriptor) & ACTIVE == 0)?;
        self.clear_endpoint_interrupt(descriptor);
        Ok(())
    }

    fn clear_endpoint_interrupt(&self, descriptor: usize) {
        let interrupt = match descriptor {
            EP0_OUT_DESCRIPTOR => usb_combo::bits::IntstatT::Ep0out::SET.value,
            EP0_IN_DESCRIPTOR => usb_combo::bits::IntstatT::Ep0in::SET.value,
            _ => 0,
        };
        self.controller.clear_interrupts(interrupt);
    }

    fn wait_until(&self, mut condition: impl FnMut() -> bool) -> Result<(), LpcipUsbError> {
        match self.poll_limit {
            Some(poll_limit) => {
                for _ in 0..poll_limit {
                    if condition() {
                        return Ok(());
                    }
                }
                Err(LpcipUsbError::Timeout)
            }
            None => loop {
                if condition() {
                    return Ok(());
                }
            },
        }
    }

    fn buffer_offset(offset: usize) -> u32 {
        ((offset >> 6) as u32) & BUFFER_OFFSET_MASK
    }

    fn buffer_descriptor(offset: usize, length: usize) -> u32 {
        Self::buffer_offset(offset) | ((length as u32) << NBYTES_SHIFT)
    }

    fn write_buffer(&self, offset: usize, data: &[u8]) {
        for (index, chunk) in data.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_memory_word(offset / 4 + index, u32::from_le_bytes(word));
        }
    }

    fn read_memory_word(&self, index: usize) -> u32 {
        self.controller.read_memory_word(index)
    }

    fn write_memory_word(&self, index: usize, value: u32) {
        self.controller.write_memory_word(index, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn test_driver() -> LpcipUsbDriver {
        // Generated register blocks contain only integer registers and padding.
        // Leak the allocations to satisfy StaticRef's program-duration contract.
        let regs = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<usb_combo::regs::UsbCombo>()
        }));
        let memory = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<usb_dev0_mem::regs::UsbDev0Mem>()
        }));
        unsafe { LpcipUsbDriver::new(StaticRef::new(regs), StaticRef::new(memory)) }
    }

    pub(super) fn test_device1() -> DeviceController {
        let regs = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<usb_dev1::regs::UsbDev1>()
        }));
        let memory = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<usb_dev1_mem::regs::UsbDev1Mem>()
        }));
        DeviceController::Device1 {
            regs: unsafe { StaticRef::new(regs) },
            memory: unsafe { StaticRef::new(memory) },
        }
    }

    #[test]
    fn device1_remains_disabled_when_device0_initialization_fails() {
        let mut driver = test_driver().with_poll_limit(0);
        let DeviceController::Device1 { regs, memory } = test_device1() else {
            unreachable!()
        };
        regs.devcmdstat.set(
            usb_dev1::bits::DevcmdstatT::DevEn::SET.value
                | usb_dev1::bits::DevcmdstatT::Dcon::SET.value,
        );
        assert_eq!(
            driver.init_and_enumerate_with_device1(regs, memory),
            Err(LpcipUsbError::UnsupportedPhy),
        );
        assert_eq!(regs.devcmdstat.get(), KEEP_PHY_CLOCK);
        assert_eq!(regs.inten.get(), 0);
    }

    #[test]
    fn connecting_device1_preserves_device0_and_hub() {
        let driver = test_driver();
        driver.disconnect_and_initialize();
        driver.connect();
        driver.write_memory_word(SETUP_DESCRIPTOR, 0x1234);
        let device0_status = driver.controller.command_status();
        let hub_control = driver.regs.hub_control.get();

        let device1 = LpcipUsbDriver {
            regs: driver.regs,
            controller: test_device1(),
            poll_limit: Some(0),
        };
        device1.initialize_endpoints();
        device1.enable_interrupts();
        device1.connect();
        assert_eq!(driver.controller.command_status(), device0_status);
        assert_eq!(driver.regs.hub_control.get(), hub_control);
        assert_eq!(driver.read_memory_word(SETUP_DESCRIPTOR), 0x1234);
        assert_eq!(device1.controller.command_status(), device0_status);
        assert_eq!(
            device1.read_memory_word(SETUP_DESCRIPTOR),
            LpcipUsbDriver::buffer_offset(SETUP_BUFFER_OFFSET),
        );
        for descriptor in FIRST_GENERIC_DESCRIPTOR..DESCRIPTOR_COUNT {
            assert_eq!(device1.read_memory_word(descriptor), DISABLED);
        }
        device1.controller.set_command_status(
            device1.controller.command_status() | usb_dev1::bits::DevcmdstatT::DevAddr.val(5).value,
        );
        assert_eq!(driver.controller.command_status(), device0_status);
        assert_eq!(
            device1.controller.command_status() & usb_dev1::bits::DevcmdstatT::DevAddr.mask,
            5,
        );
    }

    #[test]
    fn device1_descriptors_use_only_device1_ep0_memory() {
        let driver = test_driver();
        let device1 = LpcipUsbDriver {
            regs: driver.regs,
            controller: test_device1(),
            poll_limit: Some(0),
        };
        for (descriptor_type, expected) in [
            (1, DEVICE1_DESCRIPTOR.as_bytes()),
            (2, DEVICE1_CONFIGURATION.as_slice()),
            (6, DEVICE1_QUALIFIER.as_slice()),
        ] {
            let setup = SetupPacket {
                bm_request_type: caliptra_mcu_ocp::usb::setup::BmRequestType(0x80),
                b_request: 6,
                w_value: [0, descriptor_type],
                w_index: [0, 0],
                w_length: 255u16.to_le(),
            };
            // No hardware completes the transfer; inspect the armed IN buffer.
            assert_eq!(device1.send_descriptor(&setup), Err(LpcipUsbError::Timeout));
            let actual: Vec<u8> = (0..expected.len().div_ceil(4))
                .flat_map(|index| {
                    device1
                        .read_memory_word(IN_BUFFER_OFFSET / 4 + index)
                        .to_le_bytes()
                })
                .collect();
            assert_eq!(&actual[..expected.len()], expected);
            assert_eq!(
                device1.read_memory_word(EP0_IN_DESCRIPTOR),
                LpcipUsbDriver::buffer_descriptor(IN_BUFFER_OFFSET, expected.len()) | ACTIVE,
            );
            assert_eq!(driver.read_memory_word(EP0_IN_DESCRIPTOR), 0);
        }
        assert_eq!(
            DEVICE1_CONFIGURATION[2] as usize,
            DEVICE1_CONFIGURATION.len()
        );
        assert_eq!(DEVICE1_CONFIGURATION[4], 1);
        assert_eq!(DEVICE1_CONFIGURATION[13], 0);
        assert_eq!(DEVICE1_CONFIGURATION[14], 0xff);
    }

    #[test]
    fn buffer_offsets_are_encoded_in_64_byte_units() {
        assert_eq!(LpcipUsbDriver::buffer_offset(SETUP_BUFFER_OFFSET), 4);
        assert_eq!(LpcipUsbDriver::buffer_offset(OUT_BUFFER_OFFSET), 5);
        assert_eq!(LpcipUsbDriver::buffer_offset(IN_BUFFER_OFFSET), 6);
    }

    #[test]
    fn ep0_out_descriptor_encodes_length_and_offset() {
        assert_eq!(
            LpcipUsbDriver::buffer_descriptor(OUT_BUFFER_OFFSET, MAX_TRANSFER_SIZE.into()),
            (u32::from(MAX_TRANSFER_SIZE) << NBYTES_SHIFT) | 5
        );
    }

    #[test]
    fn ulpi_transaction_encodes_full_register_address_and_mode() {
        assert_eq!(LpcipUsbDriver::ulpi_transaction(0x16), 0x8000_0016);
    }
}
