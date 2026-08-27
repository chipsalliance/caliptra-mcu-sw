// Licensed under the Apache-2.0 license

use caliptra_mcu_romtime::handoff::HandoffData;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut};

/// Marker for read-only access to the handoff table.
pub struct ReadOnly;
/// Marker for read-write access to the handoff table.
pub struct ReadWrite;

/// Access to the handoff table.
///
/// The `Access` generic parameter enforces read-only or read-write capabilities at compile time.
pub struct HandOff<Access> {
    _access: PhantomData<Access>,
}

impl<Access> Deref for HandOff<Access> {
    type Target = HandoffData;
    fn deref(&self) -> &Self::Target {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        // Safety: We know HANDOFF is valid because the `Self` constructor checked the FHT marker
        // and version.
        unsafe { &*addr_of!(caliptra_mcu_romtime::handoff::HANDOFF) }
    }
}

impl DerefMut for HandOff<ReadWrite> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        // Safety: We know HANDOFF is valid because the `Self` constructor checked the FHT marker
        // and version.
        unsafe { &mut *addr_of_mut!(caliptra_mcu_romtime::handoff::HANDOFF) }
    }
}

impl HandOff<ReadOnly> {
    /// Read handoff data from DCCM
    /// This returns a read-only handle to the static handoff data.
    pub fn new() -> Option<Self> {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        let data = unsafe { &mut *addr_of_mut!(caliptra_mcu_romtime::handoff::HANDOFF) };
        caliptra_mcu_romtime::println!(
            "[mcu-runtime] Checking handoff at {:p}",
            addr_of!(caliptra_mcu_romtime::handoff::HANDOFF)
        );
        if data.rom.fht_marker != caliptra_mcu_romtime::handoff::FHT_MARKER {
            return None;
        }
        if data.rom.fht_major_ver != caliptra_mcu_romtime::handoff::FHT_MAJOR_VERSION {
            caliptra_mcu_romtime::println!(
                "[mcu-runtime] ERROR: Invalid handoff major version: {}",
                data.rom.fht_major_ver
            );
            return None;
        }
        Some(Self {
            _access: PhantomData,
        })
    }
}

impl HandOff<ReadWrite> {
    /// Read the handoff data from DCCM for mutation
    ///
    /// # Safety
    /// The caller MUST ensure that no other references exist.
    pub unsafe fn new_mut() -> Option<Self> {
        match <HandOff<ReadOnly>>::new() {
            Some(_) => Some(Self {
                _access: PhantomData,
            }),
            None => None,
        }
    }
}

impl<Access> HandOff<Access> {
    /// Return the source used to boot the MCU firmware.
    pub fn firmware_boot_type(&self) -> Option<caliptra_mcu_romtime::handoff::FirmwareBootType> {
        self.deref().firmware_boot_type()
    }

    /// Return capabilities implemented by the MCU ROM image.
    pub fn mcu_rom_capabilities(
        &self,
    ) -> Option<caliptra_mcu_romtime::handoff::McuRomCapabilities> {
        self.deref().mcu_rom_capabilities()
    }

    /// Return the stable owner CMK produced by ROM when this handoff version supports it.
    pub fn stable_owner_key(
        &self,
    ) -> Option<&[u8; caliptra_mcu_romtime::handoff::STABLE_OWNER_KEY_CMK_SIZE]> {
        self.deref().stable_owner_key()
    }

    /// Get the address of the handoff table.
    pub fn addr(&self) -> *const HandoffData {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        addr_of!(caliptra_mcu_romtime::handoff::HANDOFF)
    }
}
