// Licensed under the Apache-2.0 license

#[cfg(feature = "ocp-lock")]
use crate::ocp_lock::HekState;
use crate::println;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

/// Magic number for the handoff table ("MCUH" in little-endian).
pub const FHT_MARKER: u32 = 0x4855434D;

/// Major version of the handoff table.
pub const FHT_MAJOR_VERSION: u16 = 1;

/// Minor version of the handoff table.
pub const FHT_MINOR_VERSION: u16 = 0;

/// Handoff data produced by ROM.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct RomHandoffTable {
    /// Magic Number marking start of table.
    pub fht_marker: u32,

    /// Major version of FHT.
    pub fht_major_ver: u16,

    /// Minor version of FHT.
    pub fht_minor_ver: u16,

    /// HEK state from OCP LOCK fuse population.
    #[cfg(feature = "ocp-lock")]
    pub hek_state: HekState,
    #[cfg(not(feature = "ocp-lock"))]
    pub reserved_hek: [u32; 3], // 12 bytes

    /// Stable owner key CMK handle, derived after this table's initial write.
    /// See `stable_owner_cmk_valid` and `HandoffData::store_stable_owner_cmk`.
    #[cfg(feature = "stable-owner-key")]
    pub stable_owner_cmk: [u32; 32], // 128 bytes
    #[cfg(not(feature = "stable-owner-key"))]
    pub reserved_cmk: [u32; 32], // 128 bytes

    /// Non-zero once `stable_owner_cmk` holds a derived key.
    #[cfg(feature = "stable-owner-key")]
    pub stable_owner_cmk_valid: u32,
    #[cfg(not(feature = "stable-owner-key"))]
    pub reserved_cmk_valid: u32,

    /// Reserved for future ROM handoff fields. Sized so RomHandoffTable's total
    /// size (192 bytes) is a 64-byte multiple.
    pub padding: [u8; 40],
}

impl Default for RomHandoffTable {
    fn default() -> Self {
        Self {
            fht_marker: FHT_MARKER,
            fht_major_ver: FHT_MAJOR_VERSION,
            fht_minor_ver: FHT_MINOR_VERSION,
            #[cfg(feature = "ocp-lock")]
            hek_state: HekState::default(),
            #[cfg(not(feature = "ocp-lock"))]
            reserved_hek: [0; 3],
            #[cfg(feature = "stable-owner-key")]
            stable_owner_cmk: [0; 32],
            #[cfg(not(feature = "stable-owner-key"))]
            reserved_cmk: [0; 32],
            #[cfg(feature = "stable-owner-key")]
            stable_owner_cmk_valid: 0,
            #[cfg(not(feature = "stable-owner-key"))]
            reserved_cmk_valid: 0,
            padding: [0; 40],
        }
    }
}

/// Handoff data produced or updated by Runtime.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct RuntimeHandoffTable {
    /// Placeholder for runtime data.
    pub reserved: [u8; 64], // 64 bytes
}

impl Default for RuntimeHandoffTable {
    fn default() -> Self {
        Self { reserved: [0; 64] }
    }
}

/// Top-level handoff structure stored in DCCM.
/// Resident at a well-known location in DCCM.
///
/// SAFETY: This structure MUST NOT exceed the reserved memory region size (1 KB)
/// at the end of DCCM defined in the linker scripts. Exceeding this size will cause
/// memory corruption or linker errors.
///
/// ALIGNMENT: This structure is explicitly 4-byte aligned.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone, Default)]
#[repr(C, align(4))]
pub struct HandoffData {
    /// ROM handoff table.
    pub rom: RomHandoffTable,

    /// Runtime handoff table.
    pub runtime: RuntimeHandoffTable,
}

// Enforce that the handoff data structure fits within the reserved 1KB region.
const _: () = assert!(core::mem::size_of::<HandoffData>() <= 1024);

// Enforce 4-byte alignment of the data structure.
const _: () = assert!(core::mem::align_of::<HandoffData>() == 4);

/// Arguments for initializing the handoff table.
#[derive(Debug, Default, Clone, Copy)]
pub struct HandoffArgs {
    /// HEK state from OCP LOCK fuse population.
    #[cfg(feature = "ocp-lock")]
    pub hek_state: HekState,
}

impl HandoffData {
    /// Size of the handoff data structure.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Store the derived stable owner key CMK handle for Runtime to consume.
    ///
    /// Called after `write()`, once `derive_stable_owner_key` succeeds — the CMK isn't
    /// known at the time the rest of the table is populated. Only the CMK and its
    /// validity flag are touched; the marker/version and other fields are left as-is.
    #[cfg(feature = "stable-owner-key")]
    pub fn store_stable_owner_cmk(cmk: &[u32; 32]) {
        // SAFETY: see write() below — ROM is the sole writer of this region pre-handoff.
        unsafe {
            HANDOFF.rom.stable_owner_cmk = *cmk;
            HANDOFF.rom.stable_owner_cmk_valid = 1;
        }
    }

    /// Persist handoff data structure from the given arguments.
    pub fn write(_args: HandoffArgs) {
        println!(
            "[mcu-rom] Writing handoff table (size {}) to DCCM at {:p}",
            HandoffData::SIZE as u32,
            &raw const HANDOFF
        );

        // SAFETY: Linker must allocate the HANDOFF struct. This is currently the only code writing
        // to the reserved memory section. Should that invariant change there is risk of data
        // corruption / write contention.
        unsafe {
            HANDOFF = Self {
                rom: RomHandoffTable {
                    #[cfg(feature = "ocp-lock")]
                    hek_state: _args.hek_state,
                    #[cfg(not(feature = "ocp-lock"))]
                    reserved_hek: [0; 3],
                    ..Default::default()
                },
                runtime: RuntimeHandoffTable::default(),
            }
        }
    }
}

/// Handoff data resident in the .handoff section of DCCM.
/// This section is shared between ROM and Runtime.
#[link_section = ".handoff"]
pub static mut HANDOFF: HandoffData = HandoffData {
    rom: RomHandoffTable {
        fht_marker: 0,
        fht_major_ver: 0,
        fht_minor_ver: 0,
        #[cfg(feature = "ocp-lock")]
        hek_state: HekState {
            active_state: crate::ocp_lock::HekSeedState::Unused,
            reserved: 0,
            active_slot: 0,
            total_slots: 0,
        },
        #[cfg(not(feature = "ocp-lock"))]
        reserved_hek: [0; 3],
        #[cfg(feature = "stable-owner-key")]
        stable_owner_cmk: [0; 32],
        #[cfg(not(feature = "stable-owner-key"))]
        reserved_cmk: [0; 32],
        #[cfg(feature = "stable-owner-key")]
        stable_owner_cmk_valid: 0,
        #[cfg(not(feature = "stable-owner-key"))]
        reserved_cmk_valid: 0,
        padding: [0; 40],
    },
    runtime: RuntimeHandoffTable { reserved: [0; 64] },
};
