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
pub struct CodeRegion(pub TORRegionSpec);

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

/// A RISC-V ePMP implementation which supports machine-mode (kernel) memory
/// protection by using the machine-mode lockdown mode (MML), with a fixed
/// number of "kernel regions" (such as `.text`, flash, RAM and MMIO).
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
///   +-------------------+------------------------------------+-------+---+-------+
///   | ENTRY             | REGION / ADDR                      | MODE  | L | PERMS |
///   +-------------------+------------------------------------+-------+---+-------+
///   |                 0 | ---------------------------------- | OFF   | X | ----- |
///   |                 1 | Kernel .text section               | TOR   | X | R/X   |
///   |                   |                                    |       |   |       |
///   |                 2 | /                                \ | OFF   |   |       |
///   |                 3 | \ Userspace TOR region #0        / | TOR   |   | ????? |
///   |                   |                                    |       |   |       |
///   |                 4 | /                                \ | OFF   |   |       |
///   |                 5 | \ Userspace TOR region #1        / | TOR   |   | ????? |
///   |                   |                                    |       |   |       |
///   |     n - M - U - 6 | /                                \ |       |   |       |
///   |     n - M - U - 5 | \ Userspace TOR region #x        / |       |   |       |
///   |                   |                                    |       |   |       |
///   | n - M - U - 4 ... | User MMIO                          | NAPOT |   | R/W   |
///   |                   |                                    |       |   |       |
///   |     n - M - 4 ... | Machine MMIO                       | NAPOT | X | R/W   |
///   |                   |                                    |       |   |       |
///   |             n - 4 | /                                \ | OFF   | X | ----- |
///   |             n - 3 | \ Code (spanning kernel & apps)  / | TOR   | X | R     |
///   |                   |                                    |       |   |       |
///   |             n - 2 | /                                \ | OFF   | X | ----- |
///   |             n - 1 | \ Data (spanning kernel & apps)  / | TOR   | X | R/W   |
///   +-------------------+------------------------------------+-------+---+-------|
///   ```
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
    // Start user-mode TOR regions after the first kernel .text region:
    fn tor_regions_offset(&self) -> usize {
        1
    }

    pub unsafe fn new(
        code: CodeRegion,
        data: DataRegion,
        user_mmio: &[MMIORegion],
        machine_mmio: &[MMIORegion],
        kernel_text: KernelTextRegion,
    ) -> Result<Self, ()> {
        // Ensure that the MPU_REGIONS (starting at entry, and occupying two
        // entries per region) don't overflow the available entires, excluding
        // the 6 entries used for implementing the kernel memory protection:
        let u = user_mmio.len();
        let m = machine_mmio.len();
        assert!(MPU_REGIONS <= ((AVAILABLE_ENTRIES - 6 - m - u) / 2));

        for i in 0..AVAILABLE_ENTRIES {
            reset_entry(i);
        }

        // -----------------------------------------------------------------
        // Hardware PMP is verified to be in a compatible mode & state, and
        // has at least `AVAILABLE_ENTRIES` entries. We have not yet checked
        // whether the PMP is actually an _e_PMP. However, we don't want to
        // produce a gadget to set RLB, and so the only safe way to test
        // this is to set up the PMP regions and then try to enable the
        // mseccfg bits.
        // -----------------------------------------------------------------

        // Set the kernel `.text`, flash, RAM and MMIO regions, in no
        // particular order, with the exception of `.text` and flash:
        // `.text` must precede flash, as otherwise we'd be revoking execute
        // permissions temporarily. Given that we can currently execute
        // code, this should not have any impact on our accessible memory,
        // assuming that the provided regions are not otherwise aliased.

        // `.text` at beginning
        write_pmpaddr_pmpcfg(
            0,
            (pmpcfg_octet::a::OFF
                + pmpcfg_octet::r::CLEAR
                + pmpcfg_octet::w::CLEAR
                + pmpcfg_octet::x::CLEAR
                + pmpcfg_octet::l::SET)
                .into(),
            (kernel_text.0.start() as usize) >> 2,
        );
        write_pmpaddr_pmpcfg(
            1,
            (pmpcfg_octet::a::TOR
                + pmpcfg_octet::r::SET
                + pmpcfg_octet::w::CLEAR
                + pmpcfg_octet::x::SET
                + pmpcfg_octet::l::SET)
                .into(),
            (kernel_text.0.end() as usize) >> 2,
        );

        // user MMIO at n - m - u - 4
        for (i, mmio) in user_mmio.iter().enumerate() {
            write_pmpaddr_pmpcfg(
                AVAILABLE_ENTRIES - m - u - 4 + i,
                (pmpcfg_octet::a::NAPOT
                    + pmpcfg_octet::r::CLEAR
                    + pmpcfg_octet::w::SET
                    + pmpcfg_octet::x::SET
                    + pmpcfg_octet::l::CLEAR) // shared region, R/W for both U and M
                    .into(),
                mmio.0.napot_addr(),
            );
        }

        // machine MMIO at n - m - 4
        for (i, mmio) in machine_mmio.iter().enumerate() {
            write_pmpaddr_pmpcfg(
                AVAILABLE_ENTRIES - m - 4 + i,
                (pmpcfg_octet::a::NAPOT
                    + pmpcfg_octet::r::SET
                    + pmpcfg_octet::w::SET
                    + pmpcfg_octet::x::CLEAR
                    + pmpcfg_octet::l::SET)
                    .into(),
                mmio.0.napot_addr(),
            );
        }

        // code at n - 4 .. n - 3:
        write_pmpaddr_pmpcfg(
            AVAILABLE_ENTRIES - 4,
            (pmpcfg_octet::a::OFF
                + pmpcfg_octet::r::CLEAR
                + pmpcfg_octet::w::CLEAR
                + pmpcfg_octet::x::CLEAR
                + pmpcfg_octet::l::SET)
                .into(),
            (code.0.start() as usize) >> 2,
        );
        write_pmpaddr_pmpcfg(
            AVAILABLE_ENTRIES - 3,
            (pmpcfg_octet::a::TOR
                + pmpcfg_octet::r::SET
                + pmpcfg_octet::w::CLEAR
                + pmpcfg_octet::x::CLEAR
                + pmpcfg_octet::l::SET)
                .into(),
            (code.0.end() as usize) >> 2,
        );

        // data at n - 2 .. n - 1:
        write_pmpaddr_pmpcfg(
            AVAILABLE_ENTRIES - 2,
            (pmpcfg_octet::a::OFF
                + pmpcfg_octet::r::CLEAR
                + pmpcfg_octet::w::CLEAR
                + pmpcfg_octet::x::CLEAR
                + pmpcfg_octet::l::SET)
                .into(),
            (data.0.start() as usize) >> 2,
        );
        write_pmpaddr_pmpcfg(
            AVAILABLE_ENTRIES - 1,
            (pmpcfg_octet::a::TOR
                + pmpcfg_octet::r::SET
                + pmpcfg_octet::w::SET
                + pmpcfg_octet::x::CLEAR
                + pmpcfg_octet::l::SET)
                .into(),
            (data.0.end() as usize) >> 2,
        );

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
            return Err(());
        }

        // Setup complete
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
