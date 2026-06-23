# NWP Phase 1 — Executive Summary

**Branch**: `dev/zahralak/nwp_phase1_rebased` (parent and `hw/caliptra-ss` submodule)
**Base**: rebased on `origin/main-2.1` (parent) + `origin/main` (submodule)
**Date**: 2026-06-02
**Full report**: [`nwp_phase1_full_report.md`](nwp_phase1_full_report.md)

---

## TL;DR

Phase 1 stands up a second VeeR EL2 RISC-V core — the **Network Coprocessor ("NWP")** — alongside the existing MCU on the Caliptra Subsystem AXI fabric. NWP has its own ROM (`0x9000_0000`), its own DCCM (64 KB at `0x3000_0000`), its own PIC, and its own three AXI master ports. The whole block is gated at compile time by an opt-in `ENABLE_NWP` macro (RTL) + matching `nwp` Cargo feature (SW), so CPU-only SKUs build without any NWP footprint. Runtime reset gating (so MCU can hold/release NWP at runtime) is still Phase 2/3 — when `ENABLE_NWP` is on today, NWP runs whenever MCU runs. Validated end-to-end in both VCS and the Rust emulator; all 4 NWP tests pass live VCS sim (2026-06-01) and the 3 Rust tests pass on the emulator.

---

## Addition of Network Processor (NWP)

![](nwp_phase1_picture.svg)

---

## What was built

| Layer | Net new |
|---|---|
| **RTL** (submodule) | NWP VeeR EL2 core (`css_nwp0_*` prefix), `nwp_top.sv` wrapper, testbench SRAM model, top-level integration, `ENABLE_NWP` ifdef gate, NWP VCS test suites |
| **Firmware** (`network/`) | NWP config / ROM / drivers crates |
| **Emulator** | NWP CPU instance + per-tick step, dedicated `NetworkRootBus` (NWP ROM/DCCM/UART/PIC/Ethernet); runtime-gated by `--network-rom <path>` |
| **Tests** | NWP integration tests under `tests/integration/src/network/` paired with VCS suites |

---

## MCU baseline → NWP delta

| Region / property | MCU | NWP |
|---|---|---|
| ROM base | `0x8000_0000` | `0x9000_0000` |
| DCCM | `0x5000_0000`, **16 KB** | `0x3000_0000`, **64 KB** |
| PIC base | `0x6000_0000` | `0xB000_0000` |
| Macro prefix | `css_mcu0_*` | `css_nwp0_*` |
| AXI master ports | 3 (lsu/ifu/sb) | 3 (lsu/ifu/sb) |
| AXI slave ports | 1 (`mcu_rom`) | 1 (`nwp_rom`) |
| Bus protocol | AXI4 | AXI4 |
| MCU mailbox (`0x2140_0000`) | owns | reachable as master (Phase 2 hook) |
| Reset | `cptra_ss_mcu_rst_b_i` | shares MCU's reset (runtime gating in Phase 2) |
| Compile-time gate | none — unconditional | opt-in `ENABLE_NWP` macro (RTL); SW gated at runtime by presence of `--network-rom <path>` |

---

## Key design decisions

1. **Two cores, two macro prefixes** (`css_mcu0_*` / `css_nwp0_*`) — two cores in one elaboration unit need disjoint identifiers and disjoint memory regions; forced a second VeeR file tree and a cloned `*_top.sv` wrapper.
2. **DCCM upsized 16 KB → 64 KB** — driven by network-protocol parsing memory needs.
3. **Single source of truth** for NWP's address layout in `network/config/src/lib.rs` (`DEFAULT_NETWORK_MEMORY_MAP`) — linker, runtime, emulator, and MRAC all derive from it; eliminates a class of silent map-drift bugs MCU is exposed to. Layout: ROM `0x9000_0000` (64 KB FW / 256 KB HW), DCCM `0x3000_0000` (64 KB), PIC `0xB000_0000`, UART `0x1000_1000`, Ethernet TAP `0x1000_3000`; MCU mailbox `0x2140_0000` reachable as master.
4. **Cargo-feature test selection** — one ROM binary per feature (no ROM-side dispatch); each test image is minimal and traceable.
5. **Every test runs on both VCS (real RTL) and the Rust emulator** — the two surfaces catch different bug classes (VCS catches AXI handshake / timing issues; the emulator catches firmware logic / register-state bugs), so running both as part of the dev workflow gives broader coverage than either alone.
6. **MCU mailbox at `0x2140_0000` reachable by NWP-as-master** — Phase 2 mailbox protocol drops in with no fabric changes.
7. **Compile-time `ENABLE_NWP` gate** — first block-level conditional in `caliptra_ss_top.sv` (USB/I3C are still unconditional). Opt-in macro on the RTL side; the SW emulator gates NWP at runtime via `--network-rom <path>`, so CPU-only SKUs elaborate and link without NWP.

---

## Test results

| Suite | VCS | Emulator | Validates |
|---|---|---|---|
| `nwp_hello_world` | PASS | PASS | Boot reaches `main()`, UART OK |
| `nwp_hello_world_c` | PASS | n/a | Same flow, C-language firmware |
| `nwp_dccm` | PASS | PASS | DCCM integrity (4 patterns × 16 words) |
| `nwp_exception` | PASS | PASS | `unimp` traps to handler, prints `mcause` / `mepc` |
| `test_network_cpu_rom_start` | n/a | PASS | NWP exists and produces UART output |
| `test_network_rom_dhcp_with_server` | n/a | PASS | DHCP discover/offer via host TAP + dnsmasq |

Live VCS pass: 2026-06-01.

---

## What Phase 1 deliberately did NOT do

- No runtime reset gating (compile-time `ENABLE_NWP` is in place; runtime hold/release via MCI register is Phase 2/3)
- No NWP↔MCU communication
- No NWP role in MCU boot
- No FPGA bring-up
- No real-silicon Ethernet PHY mapping (emulator uses host TAP)

These are the explicit Phase 2 / Phase 3 targets.

---

## MCU test parity (open work — pending Bharat sign-off)

The three Phase-1 NWP self-tests in tree (`nwp_hello_world`, `nwp_dccm`, `nwp_exception`) are bring-up smokes for newly-instantiated NWP hardware, **not ports of MCU tests** — no `mcu_dccm` or `mcu_exception` exists in `caliptra-ss/src/integration/test_suites/`, and `mcu_hello_world` is C-only.

Applying Bharat's `[M1]` *"literally a replication of the existing blocks"* principle to the **test surface** suggests one additional Phase-1 port (**needs Bharat sign-off**):

| MCU test                     | NWP counterpart       | Why                                                                              |
| ---------------------------- | --------------------- | -------------------------------------------------------------------------------- |
| `smoke_test_mcu_trace_buffer`| `nwp_trace_buffer`    | Confirms NWP VeeR trace-buffer wiring (independent of MCU's)                    |

Skipped permanently in Phase 1 because NWP hardware doesn't have them: `mcu_lmem_exe` and `smoke_test_mcu_sram_*` (no SRAM execution region per REQ-4 + REQ-15; pending Bharat confirmation per `nwp_uarch_spec.md` §6.3), `caliptra_ss_mcu_sram_to_sha`, `mcu_i3c_*`, `mcu_mctp_smoke_test`.

Phase 2 / Phase 3 parity recommendations (mailbox + streaming-boot ports for Phase 2; reset-lock / AXI-ID / WDT / fuse smokes for Phase 3) are tracked in the spec at `nwp_uarch_spec.md` §12.4 and gated on Bharat sign-off there.
