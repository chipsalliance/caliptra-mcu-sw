// Licensed under the Apache-2.0 license

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut};
use romtime::handoff::HandoffData;

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
        unsafe { &*addr_of!(romtime::handoff::HANDOFF) }
    }
}

impl DerefMut for HandOff<ReadWrite> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        // Safety: We know HANDOFF is valid because the `Self` constructor checked the FHT marker
        // and version.
        unsafe { &mut *addr_of_mut!(romtime::handoff::HANDOFF) }
    }
}

impl HandOff<ReadOnly> {
    /// Read handoff data from DCCM
    /// This returns a read-only handle to the static handoff data.
    pub fn new() -> Option<Self> {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        let data = unsafe { &mut *addr_of_mut!(romtime::handoff::HANDOFF) };
        romtime::println!(
            "[mcu-runtime] Checking handoff at {:p}",
            addr_of!(romtime::handoff::HANDOFF)
        );
        if data.rom.fht_marker != romtime::handoff::FHT_MARKER {
            return None;
        }
        if data.rom.fht_major_ver != romtime::handoff::FHT_MAJOR_VERSION {
            romtime::println!(
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
    /// Get the address of the handoff table.
    pub fn addr(&self) -> *const HandoffData {
        // Safety: Linker MUST place this static object in the `.handoff` section.
        addr_of!(romtime::handoff::HANDOFF)
    }
}
