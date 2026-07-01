// Licensed under the Apache-2.0 license

use core::fmt;

pub struct Hex32(pub u32);

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

#[cfg(feature = "defmt-transport")]
impl defmt::Format for Hex32 {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{=u32:08x}", self.0)
    }
}

pub struct Bytes<'a>(pub &'a [u8]);

impl fmt::Display for Bytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(feature = "defmt-transport")]
impl defmt::Format for Bytes<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{=[u8]}", self.0)
    }
}

pub struct Dbg<T: fmt::Debug>(pub T);

impl<T: fmt::Debug> fmt::Display for Dbg<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[cfg(feature = "defmt-transport")]
impl<T: fmt::Debug> defmt::Format for Dbg<T> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}", defmt::Debug2Format(&self.0))
    }
}
