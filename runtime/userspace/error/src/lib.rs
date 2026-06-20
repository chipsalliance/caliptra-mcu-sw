// Licensed under the Apache-2.0 license

//! Unified runtime-userspace error type for the MCU stack.
//!
//! Every userspace runtime API (transports, codecs, SPDM, PLDM, MCTP-VDM,
//! mailbox, application code) returns the same `Result<T, McuErrorCode>` so
//! that **no per-layer translation is needed**. The error is a `u32`,
//! cheap to pass via registers and niche-friendly in `Result<T, _>`.
//!
//! # Layout
//!
//! ```text
//!  31      24 23      16 15            0
//! +----------+----------+----------------+
//! |  domain  | subdomain|     code       |
//! |   u8     |   u8     |     u16        |
//! +----------+----------+----------------+
//! ```
//!
//! * `domain` — top-level component (see [`domain`]).
//! * `subdomain` — sub-component within the domain (e.g. MCTP vs DOE).
//! * `code` — the actual specific error within `(domain, subdomain)`.
//!
//! For wire-protocol errors that have a canonical byte assigned by a
//! spec (SPDM DSP0274 §10.10.2, PLDM completion codes, …), protocol
//! crates encode the spec byte directly in the low bits of `code` so
//! responders can extract it losslessly when emitting an error PDU.
//!
//! # Where do constants live?
//!
//! This crate owns only **truly generic** codes that have a single
//! canonical meaning regardless of caller (`OUT_OF_MEMORY`,
//! `INTERNAL_BUG`, etc.). Protocol-specific codes live in the
//! protocol's own `errors` module — that crate also owns its
//! subdomain bytes inside its domain.

#![no_std]
#![forbid(unsafe_code)]

/// Unified runtime-userspace error code.
///
/// See the [crate-level docs](crate) for the bit layout and ownership
/// rules.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct McuErrorCode(pub u32);

/// Convenience alias for `core::result::Result<T, McuErrorCode>`.
pub type McuResult<T> = core::result::Result<T, McuErrorCode>;

impl McuErrorCode {
    /// Constructs an error code from `(domain, subdomain, code)`.
    ///
    /// This is the canonical constructor. Protocol crates wrap it in
    /// domain-specific helpers (e.g. `spdm_wire(u8)`) in their own
    /// `errors` modules.
    #[inline]
    pub const fn new(domain: u8, subdomain: u8, code: u16) -> Self {
        Self(((domain as u32) << 24) | ((subdomain as u32) << 16) | code as u32)
    }

    /// Domain byte (bits 31..24).
    #[inline]
    pub const fn domain(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Subdomain byte (bits 23..16).
    #[inline]
    pub const fn subdomain(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// Code (bits 15..0).
    #[inline]
    pub const fn code(self) -> u16 {
        self.0 as u16
    }

    /// Raw 32-bit representation.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Wraps a libtock syscall error.
    ///
    /// This is the **single boundary translation** in the whole
    /// userspace stack: anywhere a libtock-rs `ErrorCode` enters
    /// userspace, it crosses through here exactly once via the
    /// blanket `From` impl below.
    #[inline]
    pub const fn kernel(e: u16) -> Self {
        Self::new(domain::KERNEL, 0, e)
    }

    /// `true` if this error came from the kernel-syscall boundary.
    #[inline]
    pub const fn is_kernel(self) -> bool {
        self.domain() == domain::KERNEL
    }

    /// Recovers the libtock `ErrorCode` raw value if this error is
    /// a kernel passthrough.
    #[inline]
    pub const fn as_kernel(self) -> Option<u16> {
        if self.is_kernel() {
            Some(self.code())
        } else {
            None
        }
    }
}

/// Top-level domain registry (the high byte of every [`McuErrorCode`]).
///
/// Append-only: assigned bytes must never be reused for a different
/// component. The registry is **minimal** — a domain is only added
/// here when at least one caller actually produces errors in it.
/// Subdomain and code allocations within each domain are owned by the
/// corresponding protocol crate.
pub mod domain {
    /// Reserved — `0x00` never appears in `Err` (`McuErrorCode(0)` is
    /// the niche).
    pub const RESERVED: u8 = 0x00;

    /// Tock-syscall passthrough (`libtock_platform::ErrorCode`).
    pub const KERNEL: u8 = 0x01;

    /// SPDM protocol (DMTF DSP0274) — covers spdm-lite-codec,
    /// spdm-lite-stack, spdm-lite-pal, spdm-lite-transports (MCTP /
    /// DOE used by SPDM), and SPDM-carried vendor handlers (TDISP,
    /// IDE-KM, OCP-VDM). Subdomains partition these areas.
    pub const SPDM: u8 = 0x03;

    /// PLDM protocol (DMTF DSP0240) — covers PLDM base, firmware
    /// update, transport, and firmware-device operations.
    pub const PLDM: u8 = 0x04;

    /// MCU↔Caliptra mailbox protocol (`mcu-mbox-lib`).
    pub const MAILBOX: u8 = 0x06;

    /// Memory / allocator failures (singleton — any allocator may
    /// produce these, but the meaning never varies).
    pub const MEMORY: u8 = 0x10;

    /// Internal invariants — these indicate bugs (`INTERNAL_BUG`,
    /// `NOT_IMPLEMENTED`, …).
    pub const INTERNAL: u8 = 0xFF;
}

/// Truly cross-cutting error codes — meaning doesn't depend on caller.
///
/// Protocol-specific codes (SPDM wire errors, PLDM completion codes,
/// MCTP framing errors, …) live in the **protocol crate's** own
/// `errors` module, not here.
pub mod codes {
    use super::{domain, McuErrorCode};

    /// The allocator pool was exhausted.
    pub const OUT_OF_MEMORY: McuErrorCode = McuErrorCode::new(domain::MEMORY, 0, 0x0001);

    /// An allocation request had an unsupported alignment requirement.
    pub const BAD_ALIGNMENT: McuErrorCode = McuErrorCode::new(domain::MEMORY, 0, 0x0002);

    /// A program invariant was violated — this indicates a bug.
    pub const INTERNAL_BUG: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0001);

    /// Code path is a stub / placeholder.
    pub const NOT_IMPLEMENTED: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0002);

    /// A non-local invariant (e.g. unexpected state) was hit.
    pub const INVARIANT: McuErrorCode = McuErrorCode::new(domain::INTERNAL, 0, 0x0003);

    /// Caliptra mailbox was busy (transient — caller should retry).
    pub const MAILBOX_BUSY: McuErrorCode = McuErrorCode::new(domain::MAILBOX, 0, 0x0001);
}

// ----- Boundary translations -------------------------------------------------

impl From<caliptra_mcu_libtock_platform::ErrorCode> for McuErrorCode {
    #[inline]
    fn from(e: caliptra_mcu_libtock_platform::ErrorCode) -> Self {
        McuErrorCode::kernel(e as u16)
    }
}

// `From<McuErrorCode> for u32` is useful for printf-style logging.
impl From<McuErrorCode> for u32 {
    #[inline]
    fn from(e: McuErrorCode) -> u32 {
        e.0
    }
}

// Make `McuErrorCode` directly usable in `{:08x}` style format strings —
// frees callers from having to manually convert to `u32` first, and
// keeps the existing log lines that printed the prior `u32` alias
// working without change.
impl core::fmt::LowerHex for McuErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::UpperHex for McuErrorCode {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}
