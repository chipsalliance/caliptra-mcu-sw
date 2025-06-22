// Licensed under the Apache-2.0 license

#[cfg(target_arch = "riscv32")]
use mcu_config::McuMemoryMap;
#[cfg(target_arch = "riscv32")]
use mcu_tock_veer::pmp::PMPRegionList;

/// Input from platform: a memory region with its properties
#[cfg(target_arch = "riscv32")]
#[derive(Debug, Clone, Copy)]
pub struct PlatformRegion {
    pub start_addr: *const u8,
    pub size: usize,
    pub is_mmio: bool,
    pub user_accessible: bool,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Input configuration from platform
#[cfg(target_arch = "riscv32")]
pub struct PlatformPMPConfig<'a> {
    /// All platform memory regions (kernel text, code, data, MMIO, etc.)
    pub regions: &'a [PlatformRegion],
    /// Platform memory map configuration
    pub memory_map: &'a McuMemoryMap,
}

/// Check if two regions overlap
#[cfg(target_arch = "riscv32")]
fn regions_overlap(region_a: PlatformRegion, region_b: PlatformRegion) -> bool {
    let start_a = region_a.start_addr as usize;
    let end_a = start_a + region_a.size;
    let start_b = region_b.start_addr as usize;
    let end_b = start_b + region_b.size;

    // Regions overlap if: start_a < end_b && start_b < end_a
    start_a < end_b && start_b < end_a
}

/// Check if a platform region overlaps with a memory area defined by offset/size
#[cfg(target_arch = "riscv32")]
fn region_overlaps_memory_area(region: PlatformRegion, mem_offset: u32, mem_size: u32) -> bool {
    let region_start = region.start_addr as usize;
    let region_end = region_start + region.size;
    let mem_start = mem_offset as usize;
    let mem_end = mem_start + (mem_size as usize);

    // Regions overlap if: region_start < mem_end && mem_start < region_end
    region_start < mem_end && mem_start < region_end
}

/// Try to upgrade an MMIO region to NAPOT format by expanding its size
#[cfg(target_arch = "riscv32")]
fn try_convert_to_napot(region: PlatformRegion) -> Result<PlatformRegion, PlatformRegion> {
    if !region.is_mmio {
        return Err(region); // Only convert MMIO regions
    }

    let start = region.start_addr as usize;
    let original_size = region.size;

    // Start address cannot be 0
    if start == 0 {
        return Err(region);
    }

    // Find the largest power-of-2 that start address is naturally aligned to
    // This gives us the maximum possible NAPOT size for this start address
    let max_alignment = start & (start.wrapping_neg()); // Extract lowest set bit (largest power-of-2 factor)

    // Find the smallest power-of-2 size that is >= original_size
    let mut napot_size = 1;
    while napot_size < original_size {
        napot_size <<= 1;
    }

    // NAPOT size cannot exceed the natural alignment of the start address
    if napot_size > max_alignment {
        return Err(region); // Cannot create a valid NAPOT region
    }

    // Create expanded NAPOT region
    let napot_region = PlatformRegion {
        start_addr: region.start_addr,
        size: napot_size,
        is_mmio: region.is_mmio,
        user_accessible: region.user_accessible,
        read: region.read,
        write: region.write,
        execute: region.execute,
    };

    Ok(napot_region)
}

/// Convert MMIO regions to NAPOT where possible (best effort)
#[cfg(target_arch = "riscv32")]
fn optimize_mmio_napot(regions: &mut [Option<PlatformRegion>; 32], region_count: usize) -> usize {
    // Try to convert each MMIO region to NAPOT (best effort)
    for i in 0..region_count {
        if let Some(original_region) = regions[i] {
            if original_region.is_mmio {
                if let Ok(napot_region) = try_convert_to_napot(original_region) {
                    // Temporarily set the NAPOT version
                    regions[i] = Some(napot_region);

                    // Check if this NAPOT version overlaps with any other MMIO region
                    let mut has_overlap = false;
                    for j in 0..region_count {
                        if i != j {
                            if let Some(other_region) = regions[j] {
                                if other_region.is_mmio
                                    && regions_overlap(napot_region, other_region)
                                {
                                    has_overlap = true;
                                    break;
                                }
                            }
                        }
                    }

                    if has_overlap {
                        // Revert to original region if NAPOT causes overlap
                        regions[i] = Some(original_region);
                    }
                    // Otherwise keep the NAPOT version
                }
                // If conversion fails, keep original region
            }
        }
    }

    region_count
}

/// Coalesce adjacent regions with identical properties in-place
#[cfg(target_arch = "riscv32")]
fn coalesce_regions_in_place(
    regions: &mut [Option<PlatformRegion>; 32],
    region_count: usize,
) -> usize {
    if region_count <= 1 {
        return region_count;
    }

    let mut write_pos = 0;
    let mut current_region = regions[0].unwrap();

    for read_pos in 1..region_count {
        let next_region = regions[read_pos].unwrap();

        // Check if regions are adjacent and have same properties
        let regions_adjacent =
            unsafe { current_region.start_addr.add(current_region.size) == next_region.start_addr };
        let same_properties = current_region.is_mmio == next_region.is_mmio
            && current_region.user_accessible == next_region.user_accessible
            && current_region.read == next_region.read
            && current_region.write == next_region.write
            && current_region.execute == next_region.execute;

        if regions_adjacent && same_properties {
            // Extend current region to include next region
            current_region.size += next_region.size;
        } else {
            // Write current region and start new one
            regions[write_pos] = Some(current_region);
            write_pos += 1;
            current_region = next_region;
        }
    }

    // Don't forget the last region
    regions[write_pos] = Some(current_region);
    write_pos += 1;

    // Clear any remaining slots
    for i in write_pos..region_count {
        regions[i] = None;
    }

    write_pos
}

/// Convert processed platform regions to PMP regions and add them to the list
#[cfg(target_arch = "riscv32")]
fn convert_platform_regions_to_pmp(
    pmp_list: &mut PMPRegionList,
    platform_regions: &[Option<PlatformRegion>],
) -> Result<(), ()> {
    for region_opt in platform_regions {
        let platform_region = region_opt.unwrap();

        // Convert PlatformRegion to appropriate PMPRegion variant
        let pmp_region = match (
            platform_region.is_mmio,
            platform_region.user_accessible,
            platform_region.read,
            platform_region.write,
            platform_region.execute,
        ) {
            // MMIO regions: user-accessible
            (true, true, _, _, _) => {
                // TODO: Consider adding TOR-based MMIO variants (UserMMIOTOR, MachineMMIOTOR)
                //       to support MMIO regions that don't meet NAPOT alignment/size requirements
                use mcu_tock_veer::pmp::MMIORegion;
                use rv32i::pmp::NAPOTRegionSpec;

                let napot_spec =
                    NAPOTRegionSpec::new(platform_region.start_addr, platform_region.size)
                        .ok_or_else(|| {
                            romtime::println!(
                                "Error: MMIO region cannot be converted to NAPOT format"
                            );
                            romtime::println!(
                                "  Region: {:p}+{:#x}",
                                platform_region.start_addr,
                                platform_region.size
                            );
                            romtime::println!("  NAPOT requirements:");
                            romtime::println!(
                                "    - Start address must be naturally aligned to the size"
                            );
                            romtime::println!("    - Size must be a power of 2");
                            romtime::println!(
                        "  Consider adjusting region boundaries or using separate smaller regions"
                    );
                            ()
                        })?;

                mcu_tock_veer::pmp::PMPRegion::UserMMIO(MMIORegion(napot_spec))
            }

            // MMIO regions: machine-only
            (true, false, _, _, _) => {
                use mcu_tock_veer::pmp::MMIORegion;
                use rv32i::pmp::NAPOTRegionSpec;

                let napot_spec =
                    NAPOTRegionSpec::new(platform_region.start_addr, platform_region.size)
                        .ok_or_else(|| {
                            romtime::println!(
                                "Error: MMIO region cannot be converted to NAPOT format"
                            );
                            romtime::println!(
                                "  Region: {:p}+{:#x}",
                                platform_region.start_addr,
                                platform_region.size
                            );
                            romtime::println!("  NAPOT requirements:");
                            romtime::println!(
                                "    - Start address must be naturally aligned to the size"
                            );
                            romtime::println!("    - Size must be a power of 2");
                            romtime::println!(
                        "  Consider adjusting region boundaries or using separate smaller regions"
                    );
                            ()
                        })?;

                mcu_tock_veer::pmp::PMPRegion::MachineMMIO(MMIORegion(napot_spec))
            }

            // Non-MMIO regions: Read + Execute (KernelText)
            (false, _, true, false, true) => {
                // TODO: Consider trying NAPOT format first for code regions (more efficient - 1 PMP entry vs 2)
                //       and fall back to TOR if alignment/size requirements aren't met
                use mcu_tock_veer::pmp::KernelTextRegion;
                use rv32i::pmp::TORRegionSpec;

                let tor_spec = TORRegionSpec::new(platform_region.start_addr, unsafe {
                    platform_region.start_addr.add(platform_region.size)
                })
                .ok_or(())?;

                mcu_tock_veer::pmp::PMPRegion::KernelText(KernelTextRegion(tor_spec))
            }

            // Non-MMIO regions: Read + Write (Data)
            (false, _, true, true, false) => {
                use mcu_tock_veer::pmp::DataRegion;
                use rv32i::pmp::TORRegionSpec;

                let tor_spec = TORRegionSpec::new(platform_region.start_addr, unsafe {
                    platform_region.start_addr.add(platform_region.size)
                })
                .ok_or(())?;

                mcu_tock_veer::pmp::PMPRegion::Data(DataRegion(tor_spec))
            }

            // Non-MMIO regions: Read only (ReadOnly)
            (false, _, true, false, false) => {
                use mcu_tock_veer::pmp::ReadOnlyRegion;
                use rv32i::pmp::TORRegionSpec;

                let tor_spec = TORRegionSpec::new(platform_region.start_addr, unsafe {
                    platform_region.start_addr.add(platform_region.size)
                })
                .ok_or(())?;

                mcu_tock_veer::pmp::PMPRegion::ReadOnly(ReadOnlyRegion(tor_spec))
            }

            // Invalid combinations (should never happen due to early validation)
            _ => {
                romtime::println!("Internal Error: Invalid region combination passed validation");
                romtime::println!(
                    "  Region: {:p}+{:#x}, is_mmio={}, user_accessible={}, R={}, W={}, X={}",
                    platform_region.start_addr,
                    platform_region.size,
                    platform_region.is_mmio,
                    platform_region.user_accessible,
                    platform_region.read,
                    platform_region.write,
                    platform_region.execute
                );
                return Err(());
            }
        };

        // Add the converted region to the list
        pmp_list.add_region(pmp_region)?;
    }

    Ok(())
}

/// Main function to process platform input and create PMP regions
///
/// # Region Priority System
/// When non-MMIO regions overlap, earlier entries in the platform region list
/// have higher priority. For example:
/// - If KernelTextRegion appears before ReadOnlyRegion in the list, it takes priority
/// - The overlapping area will be configured with KernelTextRegion's properties
/// - This allows fine-grained control over specific memory areas while having
///   broader regions as fallbacks
///
/// # Validation Rules
/// - MMIO regions must not overlap with each other (hard error)
/// - MMIO regions cannot have execute permissions (hard error)
/// - Non-MMIO regions must be within SRAM or DCCM boundaries (hard error)
/// - Non-MMIO regions must be machine-only (user_accessible=false) (hard error)
/// - Non-MMIO regions must have valid permission combinations: R+X, R+W, or R (hard error)
/// - Non-MMIO region overlaps are allowed with priority-based resolution (warning)
#[cfg(target_arch = "riscv32")]
pub fn create_pmp_regions(config: PlatformPMPConfig<'_>) -> Result<PMPRegionList, ()> {
    // Step 1: Create static array to collect all regions (assume max 32 regions)
    let mut all_regions: [Option<PlatformRegion>; 32] = [None; 32];
    let mut region_count = 0;

    // Step 2: Add MCU memory map regions to array
    let memory_map = config.memory_map;

    // Step 2a: Add MCU memory map regions to array (MMIO only)
    let mut add_region = |offset: u32, size: u32, properties: mcu_config::MemoryRegionType| {
        // Only add MMIO regions (side_effect = true)
        if size > 0 && region_count < 32 && properties.side_effect {
            all_regions[region_count] = Some(PlatformRegion {
                start_addr: offset as *const u8,
                size: size as usize,
                is_mmio: true,          // Always true since we're filtering for MMIO
                user_accessible: false, // MCU regions default to machine-only
                read: true,             // MMIO regions are readable
                write: true,            // MMIO regions are writable
                execute: false,         // MMIO regions are non-executable
            });
            region_count += 1;
        }
    };

    // Add all MCU memory map regions (only MMIO ones will be included due to filtering)
    add_region(
        memory_map.rom_offset,
        memory_map.rom_size,
        memory_map.rom_properties,
    ); // Will be filtered out (memory)
    add_region(
        memory_map.sram_offset,
        memory_map.sram_size,
        memory_map.sram_properties,
    ); // Will be filtered out (memory)
    add_region(
        memory_map.dccm_offset,
        memory_map.dccm_size,
        memory_map.dccm_properties,
    ); // Will be filtered out (memory)
       // MMIO - will be added, TODO: Size of PIC is hardcoded here.
    add_region(memory_map.pic_offset, 0x10000, memory_map.pic_properties);
    add_region(
        memory_map.i3c_offset,
        memory_map.i3c_size,
        memory_map.i3c_properties,
    ); // MMIO - will be added
    add_region(
        memory_map.mci_offset,
        memory_map.mci_size,
        memory_map.mci_properties,
    ); // MMIO - will be added
    add_region(
        memory_map.mbox_offset,
        memory_map.mbox_size,
        memory_map.mbox_properties,
    ); // MMIO - will be added
    add_region(
        memory_map.soc_offset,
        memory_map.soc_size,
        memory_map.soc_properties,
    ); // MMIO - will be added
    add_region(
        memory_map.otp_offset,
        memory_map.otp_size,
        memory_map.otp_properties,
    ); // MMIO - will be added
    add_region(
        memory_map.lc_offset,
        memory_map.lc_size,
        memory_map.lc_properties,
    ); // MMIO - will be added

    // Assert MCU memory map didn't exceed expected region count
    // MCU memory map has at most 7 MMIO regions, so this should never fail
    debug_assert!(
        region_count <= 16,
        "MCU memory map generated too many regions: {}",
        region_count
    );

    // Step 3: Add platform-specific regions from config with validation
    for region in config.regions {
        if region.size == 0 {
            continue; // Skip empty regions
        }

        if region_count >= 32 {
            return Err(()); // Too many regions to fit in array
        }

        // Step 3a: Validation logic
        if region.is_mmio {
            // For MMIO regions: cannot be executable
            if region.execute {
                return Err(()); // MMIO regions cannot be executable
            }

            // For MMIO regions: check for overlaps with existing MMIO regions
            for i in 0..region_count {
                let existing = all_regions[i].unwrap();
                if existing.is_mmio && regions_overlap(*region, existing) {
                    return Err(()); // MMIO regions cannot overlap
                }
            }
        } else {
            // For non-MMIO regions: must be machine-only (kernel regions have lock bit set)
            if region.user_accessible {
                romtime::println!("Error: User-accessible non-MMIO regions are not supported");
                romtime::println!(
                    "  Region: {:p}+{:#x}, user_accessible=true",
                    region.start_addr,
                    region.size
                );
                romtime::println!(
                    "  Non-MMIO regions (KernelText, Data, ReadOnly) are always machine-only"
                );
                romtime::println!(
                    "  For user access, use MMIO regions or configure userspace PMP separately"
                );
                return Err(());
            }

            // For non-MMIO regions: validate permission combinations early
            let valid_permissions = (region.execute && region.read && !region.write) ||  // R+X (KernelText)
                (region.read && region.write && !region.execute) ||  // R+W (Data)
                (region.read && !region.write && !region.execute); // R (ReadOnly)

            if !valid_permissions {
                romtime::println!("Error: Invalid PMP region permission combination");
                romtime::println!(
                    "  Region: {:p}+{:#x}, R={} W={} X={}",
                    region.start_addr,
                    region.size,
                    region.read,
                    region.write,
                    region.execute
                );
                romtime::println!(
                    "  Supported combinations: R+X (KernelText), R+W (Data), R (ReadOnly)"
                );
                return Err(());
            }
            // For non-MMIO regions: ensure they overlap with SRAM or DCCM
            // This also ensures that the region does not overlap with any MMIO regions
            // automatically since we dont add sram and dccm to the all_regions array
            let overlaps_sram =
                region_overlaps_memory_area(*region, memory_map.sram_offset, memory_map.sram_size);
            let overlaps_dccm =
                region_overlaps_memory_area(*region, memory_map.dccm_offset, memory_map.dccm_size);

            if !overlaps_sram && !overlaps_dccm {
                return Err(()); // Non-MMIO regions must be in SRAM or DCCM
            }

            // For non-MMIO regions: check for overlaps with existing non-MMIO regions
            // Earlier entries in the platform region list have higher priority
            for i in 0..region_count {
                let existing = all_regions[i].unwrap();
                if !existing.is_mmio && regions_overlap(*region, existing) {
                    // Non-MMIO overlap detected: earlier region takes priority
                    // This is allowed for cases like KernelTextRegion overlapping with ReadOnlyRegion
                    // where fine-grained regions should override broader regions

                    let overlap_start =
                        core::cmp::max(existing.start_addr as usize, region.start_addr as usize);
                    let existing_end = existing.start_addr as usize + existing.size;
                    let region_end = region.start_addr as usize + region.size;
                    let overlap_end = core::cmp::min(existing_end, region_end);
                    let overlap_size = overlap_end - overlap_start;

                    // Issue warning using the same printing mechanism as platform code
                    romtime::println!("Warning: PMP non-MMIO region overlap detected!");
                    romtime::println!(
                        "  Existing region (higher priority): {:p} + {:#x} bytes",
                        existing.start_addr,
                        existing.size
                    );
                    romtime::println!(
                        "  New region (lower priority):       {:p} + {:#x} bytes",
                        region.start_addr,
                        region.size
                    );
                    romtime::println!(
                        "  Overlap: {:#x}-{:#x} ({:#x} bytes)",
                        overlap_start,
                        overlap_end,
                        overlap_size
                    );
                    romtime::println!("  → Earlier region takes precedence in overlapping area");
                }
            }
        }

        // Step 3b: Add validated region
        all_regions[region_count] = Some(*region);
        region_count += 1;
    }

    // Step 5: Coalesce adjacent regions with identical properties in-place
    let coalesced_count = coalesce_regions_in_place(&mut all_regions, region_count);

    // Step 6: Optimize MMIO regions to NAPOT format where possible (best effort)
    let final_count = optimize_mmio_napot(&mut all_regions, coalesced_count);

    // Step 7: Convert processed platform regions to PMP regions
    let mut pmp_list = PMPRegionList::new();
    convert_platform_regions_to_pmp(&mut pmp_list, &all_regions[..final_count])?;

    Ok(pmp_list)
}
