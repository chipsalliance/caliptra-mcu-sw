// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.

// Based on https://github.com/tock/tock/blob/b128ae817b86706c8c4e39d27fae5c54b98659f1/arch/rv32i/src/pmp.rs
// KernelProtectionMMLEPMP

use core::cell::Cell;
use core::fmt;
use kernel::platform::mpu;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{FieldValue, LocalRegisterCopy};
use rv32i::csr;
use rv32i::pmp::PMPUserMPU;
use rv32i::pmp::{pmpcfg_octet, NAPOTRegionSpec, TORRegionSpec, TORUserPMP, TORUserPMPCFG};

const MPU_REGIONS: usize = 16;
pub const AVAILABLE_ENTRIES: usize = 64;

pub type VeeRPMP = PMPUserMPU<MPU_REGIONS, VeeRProtectionMMLEPMP>;

fn reset_entry(i: usize) {
    // Read the entry's CSR:
    let pmpcfg_csr = csr::CSR.pmpconfig_get(i / 4);

    // Extract the entry's pmpcfg octet:
    let pmpcfg: LocalRegisterCopy<u8, pmpcfg_octet::Register> =
        LocalRegisterCopy::new(pmpcfg_csr.overflowing_shr(((i % 4) * 8) as u32).0 as u8);

    // As outlined above, we never touch a locked region. Thus, bail
    // out if it's locked:
    if pmpcfg.is_set(pmpcfg_octet::l) {
        panic!("PMP region was locked");
    }

    // Now that it's not locked, we can be sure that regardless of
    // any ePMP bits, this region is either ignored or entirely
    // denied for machine-mode access. Hence, we can change it in
    // arbitrary ways without breaking our own memory access. Try to
    // flip the R/W/X bits:
    csr::CSR.pmpconfig_set(i / 4, pmpcfg_csr ^ (7 << ((i % 4) * 8)));

    // Check if the CSR changed:
    if pmpcfg_csr == csr::CSR.pmpconfig_get(i / 4) {
        // Didn't change! This means that this region is not backed
        // by HW. Return an error as `AVAILABLE_ENTRIES` is
        // incorrect:
        panic!("AVAILABLE_ENTRIES is incorrect: PMP region changes did not persist");
    }

    // Finally, turn the region off:
    csr::CSR.pmpconfig_set(i / 4, pmpcfg_csr & !(0x18 << ((i % 4) * 8)));
}

// Helper to modify an arbitrary PMP entry.
fn write_pmpaddr_pmpcfg(i: usize, pmpcfg: u8, pmpaddr: usize) {
    // Important to set the address first. Locking the pmpcfg
    // register will also lock the adress register!
    csr::CSR.pmpaddr_set(i, pmpaddr);
    csr::CSR.pmpconfig_modify(
        i / 4,
        FieldValue::<usize, csr::pmpconfig::pmpcfg::Register>::new(
            0x000000FF_usize,
            (i % 4) * 8,
            u32::from_be_bytes([0, 0, 0, pmpcfg]) as usize,
        ),
    );
}

// ---------- Kernel memory-protection PMP memory region wrapper types -----
//
// These types exist primarily to avoid argument confusion in the
// [`VeeRProtectionMMLEPMP`] constructor, which accepts the addresses of
// these memory regions as arguments. They further encode whether a region
// must adhere to the `NAPOT` or `TOR` addressing mode constraints:

/// The code (kernel + apps) RAM region address range.
///
/// Configured in the PMP as a `NAPOT` region.
#[derive(Copy, Clone, Debug)]
pub struct ReadOnlyRegion(pub TORRegionSpec);

/// The Data RAM region address range.
///
/// Configured in the PMP as a `NAPOT` region.
#[derive(Copy, Clone, Debug)]
pub struct DataRegion(pub TORRegionSpec);

/// The MMIO region address range.
///
/// Configured in the PMP as a `NAPOT` region.
#[derive(Copy, Clone, Debug)]
pub struct MMIORegion(pub NAPOTRegionSpec);

/// The PMP region specification for the kernel `.text` section.
///
/// This is to be made accessible to machine-mode as read-execute.
/// Configured in the PMP as a `TOR` region.
#[derive(Copy, Clone, Debug)]
pub struct KernelTextRegion(pub TORRegionSpec);

/// Enum containing all possible PMP region types for platform configuration
#[derive(Debug, Clone, Copy)]
pub enum PMPRegion {
    ReadOnly(ReadOnlyRegion),
    Data(DataRegion),
    KernelText(KernelTextRegion),
    UserMMIO(MMIORegion),
    MachineMMIO(MMIORegion),
}

/// Configuration result containing all PMP regions in a simple list
pub struct PMPRegionList {
    /// Fixed-size array of regions (no heap allocation)
    /// Size 16 assumes worst case that all regions are TOR regions (using 2 PMP entries each)
    /// User regions: MPU_REGIONS, Kernel regions: ~3-4, total fits within AVAILABLE_ENTRIES
    pub regions: [Option<PMPRegion>; 16],
    /// Number of actual regions used
    pub count: usize,
}

impl PMPRegionList {
    /// Create a new empty region list
    pub fn new() -> Self {
        Self {
            regions: [None; 16],
            count: 0,
        }
    }

    /// Add a region to the list
    pub fn add_region(&mut self, region: PMPRegion) -> Result<(), ()> {
        if self.count >= 16 {
            return Err(());
        }
        self.regions[self.count] = Some(region);
        self.count += 1;
        Ok(())
    }

    /// Iterate through all regions
    pub fn iter(&self) -> impl Iterator<Item = &PMPRegion> {
        self.regions[..self.count].iter().filter_map(|r| r.as_ref())
    }
}

impl fmt::Display for PMPRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PMPRegion::ReadOnly(region) => {
                write!(
                    f,
                    "ReadOnly({:#x}..{:#x}) [TOR, R--, LOCK]",
                    region.0.start() as usize,
                    region.0.end() as usize
                )
            }
            PMPRegion::Data(region) => {
                write!(
                    f,
                    "Data({:#x}..{:#x}) [TOR, RW-, LOCK]",
                    region.0.start() as usize,
                    region.0.end() as usize
                )
            }
            PMPRegion::KernelText(region) => {
                write!(
                    f,
                    "KernelText({:#x}..{:#x}) [TOR, R-X, LOCK]",
                    region.0.start() as usize,
                    region.0.end() as usize
                )
            }
            PMPRegion::UserMMIO(region) => {
                write!(
                    f,
                    "UserMMIO({:#x}+{:#x}) [NAPOT, RW-, USER]",
                    region.0.start() as usize,
                    region.0.size()
                )
            }
            PMPRegion::MachineMMIO(region) => {
                write!(
                    f,
                    "MachineMMIO({:#x}+{:#x}) [NAPOT, RW-, LOCK]",
                    region.0.start() as usize,
                    region.0.size()
                )
            }
        }
    }
}

impl fmt::Display for PMPRegionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PMPRegionList ({} regions):", self.count)?;
        writeln!(f, "  Format: [MODE, RWX, LOCK] where:")?;
        writeln!(
            f,
            "    MODE: TOR=Top-of-Range, NAPOT=Naturally-Aligned-Power-of-Two"
        )?;
        writeln!(f, "    RWX:  R=Read, W=Write, X=Execute, -=Not-Allowed")?;
        writeln!(f, "    LOCK: LOCK=Locked-to-Machine, USER=User-Accessible")?;
        writeln!(
            f,
            "  PMP Entry Layout: User regions (0..{}), Kernel regions ((64-N)..63)",
            MPU_REGIONS * 2 - 1
        )?;
        for (i, region) in self.iter().enumerate() {
            writeln!(f, "  [{}]: {}", i, region)?;
        }
        Ok(())
    }
}

/// A RISC-V ePMP implementation which supports machine-mode (kernel) memory
/// protection by using the machine-mode lockdown mode (MML), with direct
/// 1:1 mapping from PMPRegionList to PMP hardware entries.
///
/// This implementation will configure the ePMP in the following way:
///
/// - `mseccfg` CSR:
///   ```text
///   |-------------+-----------------------------------------------+-------|
///   | MSECCFG BIT | LABEL                                         | STATE |
///   |-------------+-----------------------------------------------+-------|
///   |           0 | Machine-Mode Lockdown (MML)                   |     1 |
///   |           1 | Machine-Mode Whitelist Policy (MMWP)          |     1 |
///   |           2 | Rule-Lock Bypass (RLB)                        |     0 |
///   |-------------+-----------------------------------------------+-------|
///   ```
///
/// - `pmpaddrX` / `pmpcfgX` CSRs:
///   ```text
///   +-------------+----------------------------------------+-------+---+-------+
///   | ENTRY RANGE | USAGE                                  | MODE  | L | PERMS |
///   +-------------+----------------------------------------+-------+---+-------+
///   |     0..(M*2-1)| User MPU regions (dynamic allocation)  |       |   |       |
///   |             | - M TOR regions × 2 entries each (M=MPU_REGIONS) |   |       |
///   |             | - Configured via shadow_user_pmpcfgs  | TOR   |   | ????? |
///   |    (64-N)..63| Kernel regions (1:1 from PMPRegionList)      |   |       |
///   |             | - NAPOT regions (MMIO): 1 entry each  | NAPOT | ? | R/W   |
///   |             | - TOR regions (Code/Data): 2 entries   |       |   |       |
///   |             |   * Entry N:   start address          | OFF   | L | ----- |
///   |             |   * Entry N+1: end address            | TOR   | L | R?W?X |
///   +-------------+----------------------------------------+-------+---+-------+
///   ```
///
/// **Key Design Principles:**
/// - **1:1 Mapping**: PMPRegionList entries are written directly to PMP registers in order
/// - **Fixed Layout**: User regions occupy entries 0..(MPU_REGIONS*2-1), kernel regions use last N entries (64-N)..63
/// - **Entry Efficiency**: NAPOT regions use 1 entry, TOR regions use 2 entries
/// - **Security**: Kernel regions are locked (L=1), user regions are dynamic
/// - **Boot Override**: Kernel regions at end allow Tock to override entries during boot as needed
///
/// Crucially, this implementation relies on an unconfigured hardware PMP
/// implementing the ePMP (`mseccfg` CSR) extension, providing the Machine
/// Lockdown Mode (MML) security bit. This bit is required to ensure that
/// any machine-mode (kernel) protection regions (lock bit set) are only
/// accessible to kernel mode.
pub struct VeeRProtectionMMLEPMP {
    user_pmp_enabled: Cell<bool>,
    shadow_user_pmpcfgs: [Cell<TORUserPMPCFG>; MPU_REGIONS],
}

impl VeeRProtectionMMLEPMP {
    // Start user-mode TOR regions at entry 0 (kernel regions are at the end)
    // Entries 0..(MPU_REGIONS*2-1) are used for dynamic user MPU regions (MPU_REGIONS TOR regions × 2 entries each)
    // Entries (64-N)..63 are reserved for kernel regions from PMPRegionList (where N = kernel entries needed)
    fn tor_regions_offset(&self) -> usize {
        0
    }

    pub unsafe fn new(pmp_regions: PMPRegionList) -> Result<Self, ()> {
        // Clear all PMP entries first
        for i in 0..AVAILABLE_ENTRIES {
            reset_entry(i);
        }

        // Conservative approach: assume worst-case that all regions are TOR regions (2 entries each)
        let max_kernel_entries = pmp_regions.count * 2;

        // Ensure we don't exceed available PMP entries (reserve MPU_REGIONS*2 for user MPU)
        if max_kernel_entries > (AVAILABLE_ENTRIES - MPU_REGIONS * 2) {
            return Err(()); // Too many kernel regions
        }

        // Calculate starting entry for kernel regions (at the end of PMP entries)
        // We'll use conservative allocation but only consume what we actually need
        let kernel_start_entry = AVAILABLE_ENTRIES - max_kernel_entries;

        // Process regions from PMPRegionList in order, writing directly to PMP registers
        // This creates a 1:1 mapping from PMPRegionList to PMP hardware entries.
        //
        // PMP Entry Layout:
        // - Entries 0..(MPU_REGIONS*2-1): User MPU regions (using shadow_user_pmpcfgs for dynamic config)
        // - Entries (64-N)..63: Direct mapping from PMPRegionList regions (where N = kernel entries needed)
        // - NAPOT regions: Use 1 PMP entry each
        // - TOR regions: Use 2 PMP entries each (start=OFF, end=TOR)
        //
        // Maximum entries used: up to (MPU_REGIONS*2) for user regions + up to (64-MPU_REGIONS*2) for kernel regions = 64 total
        let mut pmp_entry = kernel_start_entry;

        for region in pmp_regions.iter() {
            match region {
                PMPRegion::KernelText(r) => {
                    // TOR region: start address (OFF) + end address (TOR with R+X)
                    write_pmpaddr_pmpcfg(
                        pmp_entry,
                        (pmpcfg_octet::a::OFF
                            + pmpcfg_octet::r::CLEAR
                            + pmpcfg_octet::w::CLEAR
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.start() as usize) >> 2,
                    );
                    write_pmpaddr_pmpcfg(
                        pmp_entry + 1,
                        (pmpcfg_octet::a::TOR
                            + pmpcfg_octet::r::SET
                            + pmpcfg_octet::w::CLEAR
                            + pmpcfg_octet::x::SET
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.end() as usize) >> 2,
                    );
                    pmp_entry += 2;
                }
                PMPRegion::ReadOnly(r) => {
                    // TOR region: start address (OFF) + end address (TOR with R only)
                    write_pmpaddr_pmpcfg(
                        pmp_entry,
                        (pmpcfg_octet::a::OFF
                            + pmpcfg_octet::r::CLEAR
                            + pmpcfg_octet::w::CLEAR
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.start() as usize) >> 2,
                    );
                    write_pmpaddr_pmpcfg(
                        pmp_entry + 1,
                        (pmpcfg_octet::a::TOR
                            + pmpcfg_octet::r::SET
                            + pmpcfg_octet::w::CLEAR
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.end() as usize) >> 2,
                    );
                    pmp_entry += 2;
                }
                PMPRegion::Data(r) => {
                    // TOR region: start address (OFF) + end address (TOR with R+W)
                    write_pmpaddr_pmpcfg(
                        pmp_entry,
                        (pmpcfg_octet::a::OFF
                            + pmpcfg_octet::r::CLEAR
                            + pmpcfg_octet::w::CLEAR
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.start() as usize) >> 2,
                    );
                    write_pmpaddr_pmpcfg(
                        pmp_entry + 1,
                        (pmpcfg_octet::a::TOR
                            + pmpcfg_octet::r::SET
                            + pmpcfg_octet::w::SET
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET)
                            .into(),
                        (r.0.end() as usize) >> 2,
                    );
                    pmp_entry += 2;
                }
                PMPRegion::UserMMIO(r) => {
                    // NAPOT region: user-accessible MMIO (R+W for both user and machine)
                    write_pmpaddr_pmpcfg(
                        pmp_entry,
                        (pmpcfg_octet::a::NAPOT
                            + pmpcfg_octet::r::CLEAR // TODO: Bug? should be set, emulator hangs if SET?
                            + pmpcfg_octet::w::SET
                            + pmpcfg_octet::x::SET
                            + pmpcfg_octet::l::CLEAR) // Not locked - accessible to both user and machine
                            .into(),
                        r.0.napot_addr(),
                    );
                    pmp_entry += 1;
                }
                PMPRegion::MachineMMIO(r) => {
                    // NAPOT region: machine-only MMIO (R+W for machine only)
                    write_pmpaddr_pmpcfg(
                        pmp_entry,
                        (pmpcfg_octet::a::NAPOT
                            + pmpcfg_octet::r::SET
                            + pmpcfg_octet::w::SET
                            + pmpcfg_octet::x::CLEAR
                            + pmpcfg_octet::l::SET) // Locked - machine-only access
                            .into(),
                        r.0.napot_addr(),
                    );
                    pmp_entry += 1;
                }
            }
        }

        // Finally, attempt to enable the MSECCFG security bits, and verify
        // that they have been set correctly. If they have not been set to
        // the written value, this means that this hardware either does not
        // support ePMP, or it was in some invalid state otherwise. We don't
        // need to read back the above regions, as we previous verified that
        // none of their entries were locked -- so writing to them must work
        // even without RLB set.
        //
        // Set RLB(2) = 0, MMWP(1) = 1, MML(0) = 1
        csr::CSR.mseccfg.set(0x00000003);

        // Read back the MSECCFG CSR to ensure that the machine's security
        // configuration was set properly. If this fails, we have set up the
        // PMP in a way that would give userspace access to kernel
        // space. The caller of this method must appropriately handle this
        // error condition by ensuring that the platform will never execute
        // userspace code!
        if csr::CSR.mseccfg.get() != 0x00000003 {
            return Err(()); // Hardware doesn't support ePMP or configuration failed
        }

        // Initialize user PMP shadow configuration (entries 0..(MPU_REGIONS*2-1) for dynamic user regions)
        const DEFAULT_USER_PMPCFG_OCTET: Cell<TORUserPMPCFG> = Cell::new(TORUserPMPCFG::OFF);
        Ok(VeeRProtectionMMLEPMP {
            user_pmp_enabled: Cell::new(false),
            shadow_user_pmpcfgs: [DEFAULT_USER_PMPCFG_OCTET; MPU_REGIONS],
        })
    }
}

impl TORUserPMP<MPU_REGIONS> for VeeRProtectionMMLEPMP {
    // this has to be checked in new()
    const CONST_ASSERT_CHECK: () = ();

    fn available_regions(&self) -> usize {
        // Always assume to have `MPU_REGIONS` usable TOR regions. We don't
        // support locking additional regions at runtime.
        MPU_REGIONS
    }

    // This implementation is specific for 32-bit systems. We use
    // `u32::from_be_bytes` and then cast to usize, as it manages to compile
    // on 64-bit systems as well. However, this implementation will not work
    // on RV64I systems, due to the changed pmpcfgX CSR layout.
    fn configure_pmp(
        &self,
        regions: &[(TORUserPMPCFG, *const u8, *const u8); MPU_REGIONS],
    ) -> Result<(), ()> {
        // Configure all of the regions' addresses and store their pmpcfg octets
        // in our shadow storage. If the user PMP is already enabled, we further
        // apply this configuration (set the pmpcfgX CSRs) by running
        // `enable_user_pmp`:
        for (i, (region, shadow_user_pmpcfg)) in regions
            .iter()
            .zip(self.shadow_user_pmpcfgs.iter())
            .enumerate()
        {
            // The ePMP in MML mode does not support read-write-execute
            // regions. If such a region is to be configured, abort. As this
            // loop here only modifies the shadow state, we can simply abort and
            // return an error. We don't make any promises about the ePMP state
            // if the configuration files, but it is still being activated with
            // `enable_user_pmp`:
            if region.0.get()
                == <TORUserPMPCFG as From<mpu::Permissions>>::from(
                    mpu::Permissions::ReadWriteExecute,
                )
                .get()
            {
                return Err(());
            }

            // Set the CSR addresses for this region (if its not OFF, in which
            // case the hardware-configured addresses are irrelevant):
            if region.0 != TORUserPMPCFG::OFF {
                csr::CSR.pmpaddr_set(
                    (i + self.tor_regions_offset()) * 2 + 0,
                    (region.1 as usize).overflowing_shr(2).0,
                );
                csr::CSR.pmpaddr_set(
                    (i + self.tor_regions_offset()) * 2 + 1,
                    (region.2 as usize).overflowing_shr(2).0,
                );
            }

            // Store the region's pmpcfg octet:
            shadow_user_pmpcfg.set(region.0);
        }

        // If the PMP is currently active, apply the changes to the CSRs:
        if self.user_pmp_enabled.get() {
            self.enable_user_pmp()?;
        }

        Ok(())
    }

    fn enable_user_pmp(&self) -> Result<(), ()> {
        // We store the "enabled" PMPCFG octets of user regions in the
        // `shadow_user_pmpcfg` field, such that we can re-enable the PMP
        // without a call to `configure_pmp` (where the `TORUserPMPCFG`s are
        // provided by the caller).

        // Could use `iter_array_chunks` once that's stable.
        let mut shadow_user_pmpcfgs_iter = self.shadow_user_pmpcfgs.iter();
        let mut i = self.tor_regions_offset();

        while let Some(first_region_pmpcfg) = shadow_user_pmpcfgs_iter.next() {
            // If we're at a "region" offset divisible by two (where "region" =
            // 2 PMP "entries"), then we can configure an entire `pmpcfgX` CSR
            // in one operation. As CSR writes are expensive, this is an
            // operation worth making:
            let second_region_opt = if i % 2 == 0 {
                shadow_user_pmpcfgs_iter.next()
            } else {
                None
            };

            if let Some(second_region_pmpcfg) = second_region_opt {
                // We're at an even index and have two regions to configure, so
                // do that with a single CSR write:
                csr::CSR.pmpconfig_set(
                    i / 2,
                    u32::from_be_bytes([
                        second_region_pmpcfg.get().get(),
                        TORUserPMPCFG::OFF.get(),
                        first_region_pmpcfg.get().get(),
                        TORUserPMPCFG::OFF.get(),
                    ]) as usize,
                );

                i += 2;
            } else if i % 2 == 0 {
                // This is a single region at an even index. Thus, modify the
                // first two pmpcfgX octets for this region.
                csr::CSR.pmpconfig_modify(
                    i / 2,
                    FieldValue::<usize, csr::pmpconfig::pmpcfg::Register>::new(
                        0x0000FFFF,
                        0, // lower two octets
                        u32::from_be_bytes([
                            0,
                            0,
                            first_region_pmpcfg.get().get(),
                            TORUserPMPCFG::OFF.get(),
                        ]) as usize,
                    ),
                );

                i += 1;
            } else {
                // This is a single region at an odd index. Thus, modify the
                // latter two pmpcfgX octets for this region.
                csr::CSR.pmpconfig_modify(
                    i / 2,
                    FieldValue::<usize, csr::pmpconfig::pmpcfg::Register>::new(
                        0x0000FFFF,
                        16, // higher two octets
                        u32::from_be_bytes([
                            0,
                            0,
                            first_region_pmpcfg.get().get(),
                            TORUserPMPCFG::OFF.get(),
                        ]) as usize,
                    ),
                );

                i += 1;
            }
        }

        self.user_pmp_enabled.set(true);

        Ok(())
    }

    fn disable_user_pmp(&self) {
        // Simply set all of the user-region pmpcfg octets to OFF:

        let mut user_region_pmpcfg_octet_pairs =
            (self.tor_regions_offset())..(self.tor_regions_offset() + MPU_REGIONS);
        while let Some(first_region_idx) = user_region_pmpcfg_octet_pairs.next() {
            let second_region_opt = if first_region_idx % 2 == 0 {
                user_region_pmpcfg_octet_pairs.next()
            } else {
                None
            };

            if let Some(_second_region_idx) = second_region_opt {
                // We're at an even index and have two regions to configure, so
                // do that with a single CSR write:
                csr::CSR.pmpconfig_set(
                    first_region_idx / 2,
                    u32::from_be_bytes([
                        TORUserPMPCFG::OFF.get(),
                        TORUserPMPCFG::OFF.get(),
                        TORUserPMPCFG::OFF.get(),
                        TORUserPMPCFG::OFF.get(),
                    ]) as usize,
                );
            } else if first_region_idx % 2 == 0 {
                // This is a single region at an even index. Thus, modify the
                // first two pmpcfgX octets for this region.
                csr::CSR.pmpconfig_modify(
                    first_region_idx / 2,
                    FieldValue::<usize, csr::pmpconfig::pmpcfg::Register>::new(
                        0x0000FFFF,
                        0, // lower two octets
                        u32::from_be_bytes([
                            0,
                            0,
                            TORUserPMPCFG::OFF.get(),
                            TORUserPMPCFG::OFF.get(),
                        ]) as usize,
                    ),
                );
            } else {
                // This is a single region at an odd index. Thus, modify the
                // latter two pmpcfgX octets for this region.
                csr::CSR.pmpconfig_modify(
                    first_region_idx / 2,
                    FieldValue::<usize, csr::pmpconfig::pmpcfg::Register>::new(
                        0x0000FFFF,
                        16, // higher two octets
                        u32::from_be_bytes([
                            0,
                            0,
                            TORUserPMPCFG::OFF.get(),
                            TORUserPMPCFG::OFF.get(),
                        ]) as usize,
                    ),
                );
            }
        }

        self.user_pmp_enabled.set(false);
    }
}

impl fmt::Display for VeeRProtectionMMLEPMP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            " ePMP configuration:\r\n  mseccfg: {:#08X}, user-mode PMP active: {:?}, entries:\r\n",
            csr::CSR.mseccfg.get(),
            self.user_pmp_enabled.get()
        )?;
        unsafe { rv32i::pmp::format_pmp_entries::<AVAILABLE_ENTRIES>(f) }?;

        write!(f, "  Shadow PMP entries for user-mode:\r\n")?;
        for (i, shadowed_pmpcfg) in self.shadow_user_pmpcfgs.iter().enumerate() {
            let (start_pmpaddr_label, startaddr_pmpaddr, endaddr, mode) =
                if shadowed_pmpcfg.get() == TORUserPMPCFG::OFF {
                    (
                        "pmpaddr",
                        csr::CSR.pmpaddr_get((i + self.tor_regions_offset()) * 2),
                        0,
                        "OFF",
                    )
                } else {
                    (
                        "  start",
                        csr::CSR
                            .pmpaddr_get((i + self.tor_regions_offset()) * 2)
                            .overflowing_shl(2)
                            .0,
                        csr::CSR
                            .pmpaddr_get((i + self.tor_regions_offset()) * 2 + 1)
                            .overflowing_shl(2)
                            .0
                            | 0b11,
                        "TOR",
                    )
                };

            write!(
                f,
                "  [{:02}]: {}={:#010X}, end={:#010X}, cfg={:#04X} ({}  ) ({}{}{}{})\r\n",
                (i + self.tor_regions_offset()) * 2 + 1,
                start_pmpaddr_label,
                startaddr_pmpaddr,
                endaddr,
                shadowed_pmpcfg.get().get(),
                mode,
                if shadowed_pmpcfg.get().get_reg().is_set(pmpcfg_octet::l) {
                    "l"
                } else {
                    "-"
                },
                if shadowed_pmpcfg.get().get_reg().is_set(pmpcfg_octet::r) {
                    "r"
                } else {
                    "-"
                },
                if shadowed_pmpcfg.get().get_reg().is_set(pmpcfg_octet::w) {
                    "w"
                } else {
                    "-"
                },
                if shadowed_pmpcfg.get().get_reg().is_set(pmpcfg_octet::x) {
                    "x"
                } else {
                    "-"
                },
            )?;
        }

        Ok(())
    }
}
