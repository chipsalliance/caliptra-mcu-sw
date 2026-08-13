// Licensed under the Apache-2.0 license

// Deterministic test fixture for the debug log, host-side seeded into the
// kernel `logging_flash` partition before the firmware starts. Total payload
// is just over the 900-byte MCTP VDM per-call cap (forces multi-call drain)
// and fits the MCU mailbox 4 KiB budget in a single call.
pub static TEST_DEBUG_LOG_ENTRIES: &[&[u8]] = &[
    b"[boot] mcu rom: cold-boot phase complete",
    b"[boot] mcu fmc: control handed off to fmc",
    b"[boot] mcu runtime: tasks spawning",
    b"[mctp] driver: i3c bus configured, eid 0x1d",
    b"[mctp] vdm responder: listening on dst eid",
    b"[mcu_mbox] driver: sram allocated, irq armed",
    b"[mcu_mbox] responder: waiting for caliptra rt",
    b"[spdm] context: versions 1.2/1.3 negotiated",
    b"[spdm] cert store: ldevid through rt-alias loaded",
    b"[caliptra] mailbox: idle, awaiting first command",
    b"[caliptra] runtime: detected, boot phase complete",
    b"[caliptra] dpe: init ok, context table built",
    b"[caliptra] cert: chain ready (ldevid-rt_alias)",
    b"[caliptra] device_id: retrieved from fuses",
    b"[caliptra] firmware_version: 1.2.3 active",
    b"[caliptra] uid: latched from secure storage",
    b"[caliptra] csr: export ready, keys provisioned",
    b"[mctp_vdm] firmware_version: returned v1.2.3",
    b"[mctp_vdm] device_id: canonical id returned",
    b"[mctp_vdm] device_info: uid returned",
    b"[mctp_vdm] device_capabilities: flags reported",
    b"[mcu_mbox] firmware_version: passthrough ok",
    b"[mcu_mbox] device_id: passthrough ok",
    b"[diag] heap: 12% of pool consumed",
];
