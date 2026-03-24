// Licensed under the Apache-2.0 license
//! Platform agnostic OCP LOCK logic.
//! This code may be modified by integrators without violating any OCP LOCK compliance
//! requirements.

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum HekSeedState {
    Unused = 0x0,
    Programmed = 0x1,
    ProgrammedPendingReset = 0x2,
    ProgrammedCorrupted = 0x3,
    Permanent = 0x4,
    Sanitized = 0x5,
    SanitizedPendingReset = 0x6,
    SanitizedCorrupted = 0x7,
}

impl From<HekSeedState> for u16 {
    fn from(value: HekSeedState) -> Self {
        (&value).into()
    }
}

impl From<&HekSeedState> for u16 {
    fn from(value: &HekSeedState) -> Self {
        match value {
            HekSeedState::Unused => 0x0,
            HekSeedState::Programmed => 0x1,
            HekSeedState::ProgrammedPendingReset => 0x2,
            HekSeedState::ProgrammedCorrupted => 0x3,
            HekSeedState::Permanent => 0x4,
            HekSeedState::Sanitized => 0x5,
            HekSeedState::SanitizedPendingReset => 0x6,
            HekSeedState::SanitizedCorrupted => 0x7,
        }
    }
}

// OCP LOCK v1.0rc2 hard codes this to 64 bytes.
const OCP_LOCK_KEY_MEK_SIZE: u32 = 64;

/// A single HEK Seed
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HekSeed<'a> {
    pub buf: &'a [u8; 48],
    pub state: HekSeedState,
}

impl HekSeed<'_> {
    pub fn state(&self) -> HekSeedState {
        self.state
    }
}

impl AsRef<[u8]> for HekSeed<'_> {
    fn as_ref(&self) -> &[u8] {
        self.buf
    }
}

/// A collection of HEK Seed buffers
pub struct HekSeeds<'a> {
    bufs: &'a [&'a [u8; 48]],
}

impl<'a> HekSeeds<'a> {
    pub fn new(bufs: &'a [&'a [u8; 48]]) -> Self {
        Self { bufs }
    }

    pub fn len(&self) -> usize {
        self.bufs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }

    pub fn get(&self, slot: usize) -> Option<&'a [u8; 48]> {
        self.bufs.get(slot).copied()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum PermaBitStatus {
    #[default]
    Unset,
    Set,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Error(u32);

impl Error {
    pub const INVALID_HEK_SLOT: Self = Self(0x0000_0000_0000_0001);
    pub const EXHAUSTED_HEK_SLOTS: Self = Self(0x0000_0000_0000_0002);
    pub const MISSING_PLATFORM_IMPLEMENTATION: Self = Self(0x0000_0000_0000_0003);
}

#[derive(Debug)]
pub struct HekState {
    pub active_state: HekSeedState,
    pub active_slot: usize,
    pub total_slots: usize,
}

// TODO(clundin): Clean up the trait once most of the implementation is completed.

/// Platform specific OCP LOCK behavior
pub trait Platform {
    /// Total number of HEK Seed Slots
    fn get_total_slots(&self) -> usize;

    /// The current HEK Seed Status of `slot`. `seed` is the fuse value of the slot.
    fn get_slot_state(
        &mut self,
        perma_bit: &PermaBitStatus,
        slot: usize,
        seed: &[u8; 48],
    ) -> Result<HekSeedState, Error>;

    /// Report the active slot
    fn get_active_slot(
        &mut self,
        perma_bit: &PermaBitStatus,
        seeds: &HekSeeds,
    ) -> Result<usize, Error>;
}

pub struct RomConfig<'a> {
    pub key_release_addr: u64,
    pub mek_size: u32,
    pub platform: Option<&'a mut dyn Platform>,
}

impl RomConfig<'_> {
    pub fn get_active_slot(
        &mut self,
        perma_bit: &PermaBitStatus,
        seeds: &HekSeeds,
    ) -> Result<usize, Error> {
        let platform = self
            .platform
            .as_mut()
            .ok_or(Error::MISSING_PLATFORM_IMPLEMENTATION)?;
        platform.get_active_slot(perma_bit, seeds)
    }

    pub fn get_total_slots(&mut self) -> Result<usize, Error> {
        let platform = self
            .platform
            .as_mut()
            .ok_or(Error::MISSING_PLATFORM_IMPLEMENTATION)?;
        Ok(platform.get_total_slots())
    }

    pub fn get_slot_status(
        &mut self,
        perma_bit: &PermaBitStatus,
        slot: usize,
        seed: &[u8; 48],
    ) -> Result<HekSeedState, Error> {
        let platform = self
            .platform
            .as_mut()
            .ok_or(Error::MISSING_PLATFORM_IMPLEMENTATION)?;
        platform.get_slot_state(perma_bit, slot, seed)
    }
}

impl Default for RomConfig<'_> {
    fn default() -> Self {
        Self {
            key_release_addr: 0,
            mek_size: OCP_LOCK_KEY_MEK_SIZE,
            platform: None,
        }
    }
}
