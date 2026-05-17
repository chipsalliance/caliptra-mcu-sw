// Licensed under the Apache-2.0 license

//! Macros that generate `Unaligned` bit-flag newtypes with
//! bitflags-style API (`contains`, `intersects`, `|`, `&`,
//! `pick_lowest`).
//!
//! Two flavors:
//!
//! - [`def_flag_set_le!`] for multi-byte storage (`le::U16` /
//!   `le::U32`). The newtype is `#[repr(transparent)]` over the LE
//!   byte-array type (alignment 1, `Unaligned` ✓), so it can sit
//!   directly inside `#[repr(C)] Unaligned` wire PDU structs.
//! - [`def_flag_set_u8!`] for single-byte storage (no LE wrapper
//!   needed).
//!
//! Generated API per type:
//! ```ignore
//! const EMPTY: Self;
//! const NAMED_BIT: Self;          // one per declared constant
//! const fn from_bits(bits: native) -> Self;
//! fn into_bits(self) -> native;
//! fn is_empty(self) -> bool;
//! fn contains(self, other: Self) -> bool;
//! fn intersects(self, other: Self) -> bool;
//! fn pick_lowest(self, other: Self) -> Self;
//! impl BitOr / BitOrAssign / BitAnd
//! ```

/// Define an `Unaligned` bit-flag newtype with `le::U16` or `le::U32`
/// storage. Pass the LE storage type and its native primitive.
macro_rules! def_flag_set_le {
    (
        $(#[$attr:meta])*
        pub struct $name:ident($le:ty: $native:ty) {
            $($(#[$cattr:meta])* $cname:ident = $cval:expr),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(::zerocopy::FromBytes, ::zerocopy::IntoBytes,
                 ::zerocopy::KnownLayout, ::zerocopy::Immutable,
                 ::zerocopy::Unaligned, Copy, Clone, Default, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name($le);

        #[allow(dead_code)]
        impl $name {
            pub const EMPTY: Self = Self(<$le>::ZERO);
            $(
                $(#[$cattr])*
                pub const $cname: Self = Self(<$le>::new($cval));
            )*

            #[inline] pub const fn from_bits(bits: $native) -> Self { Self(<$le>::new(bits)) }
            #[inline] pub fn into_bits(self) -> $native { self.0.get() }

            /// `const fn` OR — usable in `const` initializers, unlike
            /// the `BitOr` operator which can't be `const` because of
            /// the `le::U*::get()` call inside `into_bits`.
            ///
            /// This works because we reach into the underlying LE byte
            /// array directly using `.0.to_bytes()` is not const either;
            /// instead we cast through `Self`'s known-layout u8 bytes.
            #[inline] pub const fn const_or(self, other: Self) -> Self {
                // SAFETY-free: every byte position can be OR'd at the
                // u8 level because the storage is just bytes — the LE
                // wrapper has no semantic content beyond byte order.
                let mut out = [0u8; core::mem::size_of::<$native>()];
                let a = self.0.to_bytes();
                let b = other.0.to_bytes();
                let mut i = 0;
                while i < out.len() {
                    out[i] = a[i] | b[i];
                    i += 1;
                }
                Self(<$le>::from_bytes(out))
            }

            #[inline] pub fn is_empty(self) -> bool { self.into_bits() == 0 }
            #[inline] pub fn contains(self, other: Self) -> bool {
                let s = self.into_bits();
                let o = other.into_bits();
                (s & o) == o
            }
            #[inline] pub fn intersects(self, other: Self) -> bool {
                (self.into_bits() & other.into_bits()) != 0
            }
            /// Lowest set bit of `(self & other)`, or `EMPTY`.
            /// Implements the SPDM "pick one mutually-supported
            /// algorithm" rule.
            #[inline] pub fn pick_lowest(self, other: Self) -> Self {
                let common = self.into_bits() & other.into_bits();
                Self::from_bits(common & common.wrapping_neg())
            }
        }
        impl ::core::ops::BitOr for $name {
            type Output = Self;
            #[inline] fn bitor(self, r: Self) -> Self { Self::from_bits(self.into_bits() | r.into_bits()) }
        }
        impl ::core::ops::BitOrAssign for $name {
            #[inline] fn bitor_assign(&mut self, r: Self) { *self = *self | r; }
        }
        impl ::core::ops::BitAnd for $name {
            type Output = Self;
            #[inline] fn bitand(self, r: Self) -> Self { Self::from_bits(self.into_bits() & r.into_bits()) }
        }
    };
}

/// Same as [`def_flag_set_le`] but for `u8`-backed flag types
/// (no LE wrapper needed since `align_of::<u8>() == 1`).
macro_rules! def_flag_set_u8 {
    (
        $(#[$attr:meta])*
        pub struct $name:ident {
            $($(#[$cattr:meta])* $cname:ident = $cval:expr),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(::zerocopy::FromBytes, ::zerocopy::IntoBytes,
                 ::zerocopy::KnownLayout, ::zerocopy::Immutable,
                 ::zerocopy::Unaligned, Copy, Clone, Default, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(u8);

        #[allow(dead_code)]
        impl $name {
            pub const EMPTY: Self = Self(0);
            $(
                $(#[$cattr])*
                pub const $cname: Self = Self($cval);
            )*

            #[inline] pub const fn from_bits(bits: u8) -> Self { Self(bits) }
            #[inline] pub const fn into_bits(self) -> u8 { self.0 }
            /// `const fn` OR — usable in `const` initializers.
            #[inline] pub const fn const_or(self, other: Self) -> Self { Self(self.0 | other.0) }
            #[inline] pub fn is_empty(self) -> bool { self.0 == 0 }
            #[inline] pub fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
            #[inline] pub fn intersects(self, other: Self) -> bool { (self.0 & other.0) != 0 }
            #[inline] pub fn pick_lowest(self, other: Self) -> Self {
                let common = self.0 & other.0;
                Self(common & common.wrapping_neg())
            }
        }
        impl ::core::ops::BitOr for $name {
            type Output = Self;
            #[inline] fn bitor(self, r: Self) -> Self { Self(self.0 | r.0) }
        }
        impl ::core::ops::BitOrAssign for $name {
            #[inline] fn bitor_assign(&mut self, r: Self) { self.0 |= r.0; }
        }
        impl ::core::ops::BitAnd for $name {
            type Output = Self;
            #[inline] fn bitand(self, r: Self) -> Self { Self(self.0 & r.0) }
        }
    };
}

pub(crate) use def_flag_set_le;
pub(crate) use def_flag_set_u8;
