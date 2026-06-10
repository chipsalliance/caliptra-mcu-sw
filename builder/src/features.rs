// Licensed under the Apache-2.0 license

pub const EMULATOR_RUNTIME_TEST_FEATURES: &[&str] = &[
    "active-i3c1",
    "test-i3c-simple",
    "test-i3c-constant-writes",
    "test-mctp-capsule-loopback",
    "test-firmware-update-streaming",
    "test-streaming-boot-flash-write-back",
    "test-firmware-update-flash",
    "test-flash-based-boot",
    "test-pldm-streaming-boot",
    "test-pldm-fw-update-e2e",
    "test-do-nothing",
    "test-caliptra-certs",
    "test-caliptra-crypto",
    "test-caliptra-mailbox",
    "test-dma",
    "test-doe-transport-loopback",
    "test-doe-user-loopback",
    "test-doe-discovery",
    "test-get-device-state",
    "test-flash-ctrl-init",
    "test-flash-ctrl-read-write-page",
    "test-flash-ctrl-erase-page",
    "test-flash-storage-read-write",
    "test-flash-storage-erase",
    "test-flash-usermode",
    "test-log-flash-circular",
    "test-log-flash-linear",
    "test-log-flash-usermode",
    "test-mctp-ctrl-cmds",
    "test-mctp-user-loopback",
    "test-mctp-vdm-cmds",
    "test-pldm-discovery",
    "test-pldm-fw-update",
    "test-mci",
    "test-mcu-mbox-driver",
    "test-mcu-mbox-soc-requester-loopback",
    "test-mcu-mbox-cmds",
    "test-mbox-sram",
    "test-external-otp",
    "test-handoff",
    "test-warm-reset",
    "test-ocp-lock",
    "test-exit-immediately",
    "test-mcu-rom-flash-access",
    "test-mcu-svn-gt-fuse",
    "test-mcu-svn-lt-fuse",
];

pub const FPGA_RUNTIME_TEST_FEATURES: &[&str] = &[
    "test-i3c-simple",
    "test-i3c-constant-writes",
    "test-mctp-capsule-loopback",
    "test-fpga-flash-ctrl",
    "test-pldm-fw-update-e2e",
    "test-firmware-update-streaming",
    "test-mcu-mbox-usermode",
    "test-mcu-mbox-cmds",
    "test-mctp-vdm-cmds",
    "test-mcu-mbox-fips-self-test",
    "test-mcu-mbox-fips-periodic",
    "test-exit-immediately",
    "test-mctp-spdm-attestation",
    "test-mctp-spdm-attestation-pcr-quote",
    "test-mctp-spdm-responder-conformance",
];

/// Release-profile runtime test features (emulator).
/// These are the subset of tests we run against the release (512 KB SRAM,
/// no debug logs) firmware to verify it boots and works correctly.
pub const RELEASE_RUNTIME_TEST_FEATURES: &[&str] = &["test-flash-based-boot"];

/// ROM-only test features that need a prebuilt ROM but no custom runtime.
/// These features exist in both the emulator and FPGA ROM crates; the
/// standard runtime is used unmodified.
pub const ROM_ONLY_TEST_FEATURES: &[&str] = &[
    "ocp-lock",
    "stable-owner-key",
    "test-dot-recovery",
    "test-fw-manifest-dot",
    "test-fw-manifest-dot-hitless",
    "test-i3c-services",
    "test-rom-hooks",
    "test-svn-manifest",
    "test-usb-ocp-recovery",
];

/// A single ROM build target (platform + feature combo). Shared between
/// `cargo xtask sizes` (size reporting), `test_panic_missing` (panic-free
/// audit), and any other per-variant build check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RomVariant {
    /// Platform name passed to `--platform`. `None` defaults to `"emulator"`.
    pub platform: Option<&'static str>,
    /// Feature list passed to `--features`. `None` builds with no extra
    /// features (the crate's default feature set).
    pub features: Option<&'static str>,
}

impl RomVariant {
    pub const fn new(platform: Option<&'static str>, features: Option<&'static str>) -> Self {
        Self { platform, features }
    }

    /// Pretty display name suitable for tables, logs, and error messages.
    pub fn display(&self) -> String {
        let platform = self.platform.unwrap_or("emulator");
        match self.features {
            Some(f) if !f.is_empty() => format!("{platform} [{f}]"),
            _ => format!("{platform} (default)"),
        }
    }
}

/// Default set of ROM variants exercised by per-variant checks
/// (`cargo xtask sizes`, `test_panic_missing`, etc.).
///
/// Mirrors what `cargo xtask all-build` builds for CI, so any size
/// regression or panic introduction in a feature ROM is caught by
/// `cargo xtask precheckin`.
pub const ROM_VARIANTS: &[RomVariant] = &[
    // === emulator ===
    RomVariant::new(None, None),
    RomVariant::new(None, Some("hw-2-1")),
    // ROM_ONLY_TEST_FEATURES — kept in sync with builder/src/all.rs.
    RomVariant::new(None, Some("test-i3c-services")),
    RomVariant::new(None, Some("test-fw-manifest-dot")),
    RomVariant::new(None, Some("test-fw-manifest-dot-hitless")),
    RomVariant::new(None, Some("test-dot-recovery")),
    RomVariant::new(None, Some("test-rom-hooks")),
    // Explicit-feature ROMs tested by precheckin / all-build.
    RomVariant::new(None, Some("test-flash-based-boot")),
    // === fpga ===
    RomVariant::new(Some("fpga"), None),
    RomVariant::new(Some("fpga"), Some("hw-2-1")),
    RomVariant::new(Some("fpga"), Some("hw-2-1,test-rom-hooks")),
];

/// Parse a `--variants` CLI value into a list of [`RomVariant`].
///
/// Syntax: comma-separated list of `platform:features` items, where
/// `features` is itself a `+`-separated list (we can't use `,` as a
/// nested separator since it already separates list items). Examples:
///
/// - `emulator:` or `emulator` — emulator with no features
/// - `emulator:hw-2-1` — emulator with `hw-2-1`
/// - `emulator:hw-2-1+test-rom-hooks` — emulator with both
/// - `fpga:hw-2-1,emulator:test-i3c-services` — two variants
///
/// CLI-supplied strings are leaked via [`String::leak`] so the
/// resulting `RomVariant`s satisfy the `'static` lifetime used by
/// the const [`ROM_VARIANTS`] list (the alternative would be a
/// parallel owned variant type or `Cow`-style plumbing throughout).
/// CLI args live for the entire process anyway, so the leak is
/// inconsequential.
pub fn parse_variants(s: &str) -> Result<Vec<RomVariant>, String> {
    let mut out = Vec::new();
    for item in s.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (platform_raw, features_raw) = match item.split_once(':') {
            Some((p, f)) => (p, f),
            None => (item, ""),
        };
        let platform: Option<&'static str> = match platform_raw.trim() {
            "" | "emulator" => None,
            other => Some(other.to_string().leak()),
        };
        let features_normalized = features_raw.trim().replace('+', ",");
        let features: Option<&'static str> = if features_normalized.is_empty() {
            None
        } else {
            Some(features_normalized.leak())
        };
        out.push(RomVariant { platform, features });
    }
    if out.is_empty() {
        return Err(format!("no variants parsed from {s:?}"));
    }
    Ok(out)
}
