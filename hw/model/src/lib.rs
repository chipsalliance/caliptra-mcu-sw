// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
pub use api::mailbox::mbox_write_fifo;
pub use api_types::{DbgManufServiceRegReq, DeviceLifecycle, Fuses, U4};
use caliptra_api::{self as api, SocManager};
use caliptra_api_types as api_types;
use caliptra_emu_bus::Event;
pub use caliptra_emu_cpu::{CodeRange, ImageInfo, StackInfo, StackRange};
use caliptra_hw_model_types::{
    EtrngResponse, RandomEtrngResponses, RandomNibbles, DEFAULT_CPTRA_OBF_KEY,
};
use caliptra_registers::soc_ifc::regs::{
    CptraItrngEntropyConfig0WriteVal, CptraItrngEntropyConfig1WriteVal,
};
use mcu_rom_common::{LifecycleControllerState, LifecycleRawTokens, LifecycleToken};
pub use model_emulated::ModelEmulated;
use output::ExitStatus;
pub use output::Output;
use rand::{rngs::StdRng, SeedableRng};
use std::io::{stdout, ErrorKind};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
pub use vmem::read_otp_vmem_data;

mod bus_logger;
mod fpga_regs;
mod model_emulated;
#[cfg(feature = "fpga_realtime")]
mod model_fpga_realtime;
mod otp_provision;
mod output;
mod vmem;
mod xi3c;

pub enum ShaAccMode {
    Sha384Stream,
    Sha512Stream,
}

#[cfg(feature = "fpga_realtime")]
pub use model_fpga_realtime::ModelFpgaRealtime;

/// Ideally, general-purpose functions would return `impl HwModel` instead of
/// `DefaultHwModel` to prevent users from calling functions that aren't
/// available on all HwModel implementations.
///
/// Unfortunately, rust-analyzer (used by IDEs) can't fully resolve associated
/// types from `impl Trait`, so such functions should use `DefaultHwModel`.
/// Users should treat `DefaultHwModel` as if it were `impl HwModel`.
#[cfg(not(feature = "fpga_realtime"))]
pub type DefaultHwModel = ModelEmulated;

#[cfg(feature = "fpga_realtime")]
pub type DefaultHwModel = ModelFpgaRealtime;

pub const DEFAULT_APB_PAUSER: u32 = 0x01;

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 40_000_000; // 40 million cycles

const DEFAULT_LIFECYCLE_RAW_TOKEN: LifecycleToken =
    LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());

const DEFAULT_LIFECYCLE_RAW_TOKENS: LifecycleRawTokens = LifecycleRawTokens {
    test_unlock: [DEFAULT_LIFECYCLE_RAW_TOKEN; 7],
    manuf: DEFAULT_LIFECYCLE_RAW_TOKEN,
    manuf_to_prod: DEFAULT_LIFECYCLE_RAW_TOKEN,
    prod_to_prod_end: DEFAULT_LIFECYCLE_RAW_TOKEN,
    rma: DEFAULT_LIFECYCLE_RAW_TOKEN,
};

pub struct InitParams<'a> {
    /// The contents of the Caliptra ROM
    pub caliptra_rom: &'a [u8],
    /// Caliptra's firmware bundle.
    pub caliptra_firmware: &'a [u8],
    /// SoC manifest
    pub soc_manifest: &'a [u8],
    /// The contents of the MCU ROM
    pub mcu_rom: &'a [u8],
    /// The contents of the MCU firmware
    pub mcu_firmware: &'a [u8],

    /// The initial contents of the DCCM SRAM
    pub caliptra_dccm: &'a [u8],

    /// The initial contents of the ICCM SRAM
    pub caliptra_iccm: &'a [u8],

    /// The initial contents of the OTP memory
    pub otp_memory: Option<&'a [u8]>,

    /// The initial lifecycle controller state of the device.
    /// This will override any otp_memory contents.
    pub lifecycle_controller_state: Option<LifecycleControllerState>,

    /// Lifecycle tokens (raw) to burn into the OTP memory.
    /// This will override any otp_memory contents.
    pub lifecycle_tokens: Option<LifecycleRawTokens>,

    /// Vendor public key hash.
    /// This will override any otp_memory contents.
    pub vendor_pk_hash: Option<[u8; 48]>,

    pub log_writer: Box<dyn std::io::Write>,

    pub dbg_manuf_service: DbgManufServiceRegReq,

    pub active_mode: bool,

    // Keypairs for production debug unlock levels, from low to high
    // ECC384 and MLDSA87 keypairs
    pub prod_dbg_unlock_keypairs: Vec<(&'a [u8; 96], &'a [u8; 2592])>,

    pub bootfsm_break: bool,

    pub debug_intent: bool,

    pub uds_program_req: bool,

    // The silicon obfuscation key passed to caliptra_top.
    pub cptra_obf_key: [u32; 8],

    pub csr_hmac_key: [u32; 16],

    pub uds_granularity_32: bool,

    // 4-bit nibbles of raw entropy to feed into the internal TRNG (ENTROPY_SRC
    // peripheral).
    pub itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,

    // Pre-conditioned TRNG responses to return over the soc_ifc CPTRA_TRNG_DATA
    // registers in response to requests via CPTRA_TRNG_STATUS
    pub etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send>,

    // If true (and the HwModel supports it), initialize the SRAM with random
    // data. This will likely result in a ECC double-bit error if the CPU
    // attempts to read uninitialized memory.
    pub random_sram_puf: bool,

    // A trace path to use. If None, the CPTRA_TRACE_PATH environment variable
    // will be used
    pub trace_path: Option<PathBuf>,

    // Information about the stack Caliptra is using. When set the emulator will check if the stack
    // overflows.
    pub stack_info: Option<StackInfo>,
}
impl Default for InitParams<'_> {
    fn default() -> Self {
        let seed = std::env::var("CPTRA_TRNG_SEED")
            .ok()
            .and_then(|s| u64::from_str(&s).ok());
        let itrng_nibbles: Box<dyn Iterator<Item = u8> + Send> = if let Some(seed) = seed {
            Box::new(RandomNibbles(StdRng::seed_from_u64(seed)))
        } else {
            Box::new(RandomNibbles(StdRng::from_entropy()))
        };
        let etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send> =
            if let Some(seed) = seed {
                Box::new(RandomEtrngResponses(StdRng::seed_from_u64(seed)))
            } else {
                Box::new(RandomEtrngResponses::new_from_stdrng())
            };
        Self {
            caliptra_rom: Default::default(),
            caliptra_firmware: Default::default(),
            mcu_rom: Default::default(),
            mcu_firmware: Default::default(),
            caliptra_dccm: Default::default(),
            caliptra_iccm: Default::default(),
            otp_memory: None,
            lifecycle_controller_state: None,
            lifecycle_tokens: None,
            log_writer: Box::new(stdout()),
            dbg_manuf_service: Default::default(),
            uds_granularity_32: false, // 64-bit granularity
            bootfsm_break: false,
            uds_program_req: false,
            active_mode: false,
            prod_dbg_unlock_keypairs: Default::default(),
            debug_intent: false,
            cptra_obf_key: DEFAULT_CPTRA_OBF_KEY,
            itrng_nibbles,
            etrng_responses,
            random_sram_puf: true,
            trace_path: None,
            stack_info: None,
            csr_hmac_key: [1; 16],
            soc_manifest: Default::default(),
            vendor_pk_hash: None,
        }
    }
}

fn trace_path_or_env(trace_path: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(trace_path) = trace_path {
        return Some(trace_path);
    }
    std::env::var("CPTRA_TRACE_PATH").ok().map(PathBuf::from)
}

pub struct BootParams<'a> {
    pub fuses: Fuses,
    pub fw_image: Option<&'a [u8]>,
    pub initial_dbg_manuf_service_reg: u32,
    pub initial_repcnt_thresh_reg: Option<CptraItrngEntropyConfig1WriteVal>,
    pub initial_adaptp_thresh_reg: Option<CptraItrngEntropyConfig0WriteVal>,
    pub valid_axi_user: Vec<u32>,
    pub wdt_timeout_cycles: u64,
    // SoC manifest passed via the recovery interface
    pub soc_manifest: Option<&'a [u8]>,
    // MCU firmware image passed via the recovery interface
    pub mcu_fw_image: Option<&'a [u8]>,
}

impl Default for BootParams<'_> {
    fn default() -> Self {
        Self {
            fuses: Default::default(),
            fw_image: Default::default(),
            initial_dbg_manuf_service_reg: Default::default(),
            initial_repcnt_thresh_reg: Default::default(),
            initial_adaptp_thresh_reg: Default::default(),
            valid_axi_user: vec![0, 1, 2, 3, 4],
            wdt_timeout_cycles: EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES,
            soc_manifest: Default::default(),
            mcu_fw_image: Default::default(),
        }
    }
}

// Represents a emulator or simulation of the caliptra core hardware, to be called
// from tests. Typically, test cases should use [`crate::new()`] to create a model
// based on the cargo features (and any model-specific environment variables).
pub trait McuHwModel {
    /// Create a model. Most high-level tests should use [`new()`]
    /// instead.
    fn new_unbooted(params: InitParams) -> Result<Self>
    where
        Self: Sized;

    fn save_otp_memory(&self, path: &Path) -> Result<()>;

    /// The type name of this model
    fn type_name(&self) -> &'static str;

    /// Step execution ahead one clock cycle.
    fn step(&mut self);

    fn cycle_count(&mut self) -> u64;

    /// Any UART-ish output written by the microcontroller will be available here.
    fn output(&mut self) -> &mut Output;

    /// Execute until the result of `predicate` becomes true.
    fn step_until(&mut self, mut predicate: impl FnMut(&mut Self) -> bool) {
        while !predicate(self) {
            self.step();
        }
    }

    /// Returns true if the microcontroller has signalled that it is ready for
    /// firmware to be written to the mailbox. For RTL implementations, this
    /// should come via a caliptra_top wire rather than an APB register.
    fn ready_for_fw(&self) -> bool;

    fn step_until_exit_success(&mut self) -> std::io::Result<()> {
        self.copy_output_until_exit_success(std::io::Sink::default())
    }

    fn caliptra_soc_manager(&mut self) -> impl SocManager;

    fn copy_output_until_exit_success(
        &mut self,
        mut w: impl std::io::Write,
    ) -> std::io::Result<()> {
        loop {
            if !self.output().peek().is_empty() {
                w.write_all(self.output().take(usize::MAX).as_bytes())?;
            }
            match self.output().exit_status() {
                Some(ExitStatus::Passed) => return Ok(()),
                Some(ExitStatus::Failed) => {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        "firmware exited with failure",
                    ))
                }
                None => {}
            }
            self.step();
        }
    }

    fn step_until_exit_failure(&mut self) -> Result<()> {
        loop {
            match self.output().exit_status() {
                Some(ExitStatus::Failed) => return Ok(()),
                Some(ExitStatus::Passed) => {
                    bail!("firmware exited with success when failure was expected",);
                }
                None => {}
            }
            self.step();
        }
    }

    /// Execute until the output buffer starts with `expected_output`
    fn step_until_output(&mut self, expected_output: &str) -> Result<()> {
        self.step_until(|m| m.output().peek().len() >= expected_output.len());
        if &self.output().peek()[..expected_output.len()] != expected_output {
            bail!(
                "expected output {:?}, was {:?}",
                expected_output,
                self.output().peek()
            );
        }
        Ok(())
    }

    /// Execute until the output buffer starts with `expected_output`, and remove it
    /// from the output buffer.
    fn step_until_output_and_take(&mut self, expected_output: &str) -> Result<()> {
        self.step_until_output(expected_output)?;
        self.output().take(expected_output.len());
        Ok(())
    }

    // Execute (at least) until the output provided substr is written to the
    // output. Additional data may be present in the output after the provided
    // substr, which often happens with the fpga_realtime hardware model.
    //
    // This function will not match any data in the output that was written
    // before this function was called.
    fn step_until_output_contains(&mut self, substr: &str) -> Result<()> {
        self.output().set_search_term(substr);
        self.step_until(|m| m.output().search_matched());
        Ok(())
    }

    fn cover_fw_image(&mut self, _image: &[u8]) {}

    fn tracing_hint(&mut self, enable: bool);

    fn set_axi_user(&mut self, axi_user: u32);

    fn set_itrng_divider(&mut self, _divider: u32) {}

    fn set_generic_input_wires(&mut self, _value: &[u32; 2]) {}

    fn set_mcu_generic_input_wires(&mut self, _value: &[u32; 2]) {}

    fn set_caliptra_boot_go(&mut self, _value: bool) {}

    fn events_from_caliptra(&mut self) -> Vec<Event>;

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event>;

    fn mci_flow_status(&mut self) -> u32 {
        0
    }
}
