// Licensed under the Apache-2.0 license

//! Optional headers that may precede the MCU firmware in SRAM.
//!
//! Each header is independently optional and detected by its magic.
//! [`process_firmware_headers`] runs the active processors in a fixed
//! order, advancing an offset past each header that is present so the
//! caller knows where the firmware entry point lives.

#[cfg(any(feature = "fw-manifest-dot", feature = "svn-manifest"))]
use crate::{fatal_error, MCU_MEMORY_MAP};
use crate::{RomEnv, RomParameters};
#[cfg(feature = "svn-manifest")]
use caliptra_mcu_error::McuError;
#[cfg(any(feature = "fw-manifest-dot", feature = "svn-manifest"))]
use caliptra_mcu_romtime::HexWord;
#[cfg(any(feature = "fw-manifest-dot", feature = "svn-manifest"))]
use caliptra_mcu_romtime::McuRomBootStatus;
#[cfg(any(feature = "fw-manifest-dot", feature = "svn-manifest"))]
use core::fmt::Write;

/// Run all enabled firmware-header processors in order, returning the
/// final offset (relative to `sram_offset`) at which the firmware entry
/// point lives.
///
/// Each processor inspects SRAM at the current offset, looks for its
/// own magic, and either advances the offset past its header or leaves
/// it unchanged. A processor that finds its magic but fails validation
/// is a fatal boot error.
pub(crate) fn process_firmware_headers(
    env: &mut RomEnv,
    params: &RomParameters,
    base_offset: u32,
) -> u32 {
    #[cfg_attr(
        not(any(feature = "fw-manifest-dot", feature = "svn-manifest")),
        allow(unused_mut)
    )]
    let mut offset = base_offset;

    #[cfg(feature = "fw-manifest-dot")]
    if params.fw_manifest_dot_enabled {
        offset += process_fw_manifest_dot(env, params, offset);
    }

    #[cfg(feature = "svn-manifest")]
    if params.svn_manifest_enabled {
        offset += process_svn_manifest(env, offset);
    }

    // Suppress unused-parameter warnings when neither feature is enabled.
    let _ = (env, params);
    offset
}

#[cfg(feature = "fw-manifest-dot")]
fn process_fw_manifest_dot(env: &mut RomEnv, params: &RomParameters, offset: u32) -> u32 {
    use crate::device_ownership_transfer;
    use zerocopy::FromBytes;

    let manifest_size = core::mem::size_of::<device_ownership_transfer::FwManifestDotSection>();
    // Safety: `MCU_MEMORY_MAP.sram_offset + offset` points into MCU SRAM,
    // which has been mapped and populated by Caliptra Core before this
    // function runs. `manifest_size` bytes are within the SRAM region
    // (callers only invoke us after the static header, well below the
    // SRAM size). Byte alignment is trivially satisfied for `*const u8`.
    // We borrow the bytes immutably for the duration of the surrounding
    // header check and no aliasing mutable references exist while ROM
    // owns SRAM.
    let sram = unsafe {
        core::slice::from_raw_parts(
            (MCU_MEMORY_MAP.sram_offset + offset) as *const u8,
            manifest_size,
        )
    };

    let Ok((section, _)) = device_ownership_transfer::FwManifestDotSection::ref_from_prefix(sram)
    else {
        return 0;
    };
    if section.magic != device_ownership_transfer::FW_MANIFEST_DOT_MAGIC {
        return 0;
    }

    env.mci
        .set_flow_checkpoint(McuRomBootStatus::FwManifestDotProcessingStarted.into());
    if let Err(err) =
        device_ownership_transfer::process_fw_manifest_dot_commands(env, section, params.dot_flash)
    {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Error in firmware manifest DOT: {}",
            HexWord(err.into())
        );
        fatal_error(err);
    }
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::FwManifestDotProcessingComplete.into());
    manifest_size as u32
}

/// Look for an MCU Component SVN Manifest header at `sram_offset +
/// offset`. If the magic is present and the manifest is valid and not
/// rolled back, returns the manifest size; otherwise returns 0.
///
/// Side effects when the manifest is present: validates the structural
/// constraints, reads `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` from OTP,
/// rejects the boot if `manifest.current_svn < fuse_min_svn`, and
/// burns the fuse up to `manifest.min_svn` when it requests a higher
/// floor. All fuse interaction is gated by
/// `CPTRA_CORE_ANTI_ROLLBACK_DISABLE`.
#[cfg(feature = "svn-manifest")]
fn process_svn_manifest(env: &mut RomEnv, offset: u32) -> u32 {
    use crate::component_svn_manifest::{
        McuComponentSvnManifest, SvnLimits, MCU_COMPONENT_SVN_MANIFEST_SIZE,
    };

    // Safety: see `process_fw_manifest_dot` — same SRAM contract. The
    // 1024-byte manifest fits well within SRAM, and the caller invokes
    // us only after the static header (and any DOT section), so the
    // computed pointer stays inside the populated runtime image.
    let sram = unsafe {
        core::slice::from_raw_parts(
            (MCU_MEMORY_MAP.sram_offset + offset) as *const u8,
            MCU_COMPONENT_SVN_MANIFEST_SIZE,
        )
    };

    let manifest = match McuComponentSvnManifest::parse_if_present(sram) {
        Ok(Some(m)) => m,
        Ok(None) => return 0,
        Err(_) => {
            caliptra_mcu_romtime::println!("[mcu-rom] Component SVN Manifest header truncated");
            fatal_error(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR);
        }
    };

    env.mci
        .set_flow_checkpoint(McuRomBootStatus::ComponentSvnManifestProcessingStarted.into());

    let limits = SvnLimits {
        manifest_min_svn_max: svn_manifest_min_svn_max(),
    };
    if let Err(err) = manifest.validate(&limits) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Component SVN Manifest validation failed: {:?}",
            err
        );
        fatal_error(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR);
    }

    let anti_rollback_on = match anti_rollback_enabled(&env.otp) {
        Ok(v) => v,
        Err(err) => {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Error reading anti-rollback disable: {}",
                HexWord(err.into())
            );
            fatal_error(err);
        }
    };

    if anti_rollback_on {
        enforce_and_burn_manifest_min_svn(env, manifest);
    }

    env.mci
        .set_flow_checkpoint(McuRomBootStatus::ComponentSvnManifestProcessingComplete.into());
    MCU_COMPONENT_SVN_MANIFEST_SIZE as u32
}

/// Enforce manifest-self rollback and apply any requested
/// `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` advance:
///
/// - Reject the boot if `manifest.current_svn < fuse_min_svn`.
/// - Burn the fuse up to `manifest.min_svn` (with readback verification)
///   when the manifest requests a higher floor.
///
/// Caller must have already verified that
/// `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` is not set.
#[cfg(feature = "svn-manifest")]
fn enforce_and_burn_manifest_min_svn(
    env: &mut RomEnv,
    manifest: &crate::component_svn_manifest::McuComponentSvnManifest,
) {
    use caliptra_mcu_registers_generated::fuses::MCU_COMPONENT_SVN_MANIFEST_MIN_SVN;

    let fuse_min_svn = match env.otp.read_entry(MCU_COMPONENT_SVN_MANIFEST_MIN_SVN) {
        Ok(v) => v,
        Err(err) => {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Error reading MCU_COMPONENT_SVN_MANIFEST_MIN_SVN: {}",
                HexWord(err.into())
            );
            fatal_error(err);
        }
    };

    if u32::from(manifest.current_svn) < fuse_min_svn {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Component SVN Manifest rolled back: current_svn {} < fuse {}",
            manifest.current_svn,
            fuse_min_svn
        );
        fatal_error(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR);
    }

    if u32::from(manifest.min_svn) <= fuse_min_svn {
        return;
    }

    if let Err(err) = env
        .otp
        .write_entry(MCU_COMPONENT_SVN_MANIFEST_MIN_SVN, manifest.min_svn.into())
    {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Error burning MCU_COMPONENT_SVN_MANIFEST_MIN_SVN: {}",
            HexWord(err.into())
        );
        fatal_error(err);
    }
    let new_fuse = match env.otp.read_entry(MCU_COMPONENT_SVN_MANIFEST_MIN_SVN) {
        Ok(v) => v,
        Err(err) => {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Error reading back MCU_COMPONENT_SVN_MANIFEST_MIN_SVN: {}",
                HexWord(err.into())
            );
            fatal_error(err);
        }
    };
    if new_fuse < u32::from(manifest.min_svn) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] MCU_COMPONENT_SVN_MANIFEST_MIN_SVN readback failed: requested {}, read {}",
            manifest.min_svn,
            new_fuse
        );
        fatal_error(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR);
    }
    caliptra_mcu_romtime::println!(
        "[mcu-rom] Burned MCU_COMPONENT_SVN_MANIFEST_MIN_SVN: {} -> {}",
        fuse_min_svn,
        new_fuse
    );
}

/// Returns true iff `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` is *not* set,
/// i.e., anti-rollback enforcement is active.
#[cfg(feature = "svn-manifest")]
fn anti_rollback_enabled(otp: &caliptra_mcu_romtime::Otp) -> Result<bool, McuError> {
    let raw = otp.read_cptra_core_anti_rollback_disable()?;
    Ok(raw.iter().all(|b| *b == 0))
}

#[cfg(feature = "svn-manifest")]
fn svn_manifest_min_svn_max() -> u32 {
    use caliptra_mcu_registers_generated::fuses::{
        FuseLayoutType, MCU_COMPONENT_SVN_MANIFEST_MIN_SVN,
    };
    match MCU_COMPONENT_SVN_MANIFEST_MIN_SVN.layout {
        FuseLayoutType::OneHot { bits }
        | FuseLayoutType::OneHotLinearMajorityVote { bits, .. }
        | FuseLayoutType::OneHotLinearOr { bits, .. } => bits,
        _ => 0,
    }
}
