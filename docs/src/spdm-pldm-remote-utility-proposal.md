# Proposal: Remote SPDM & PLDM Utilities for Caliptra Subsystem

## 1. SPDM Remote Utility Options

The SPDM utility needs to act as a **requester** that can perform attestation (get version, capabilities, digests, certificates, measurements, challenge) and optionally establish secure sessions against the Caliptra MCU SPDM responder.

### Option A: Use `spdm-utils` (Western Digital) + Custom Transport

[spdm-utils](https://github.com/westerndigitalcorporation/spdm-utils) is a Rust CLI application that wraps libspdm (DMTF's C reference implementation) via FFI. It supports DOE and MCTP transports and can act as both requester and responder.

**Approach**: Fork or extend spdm-utils to add a transport backend that routes SPDM messages through our MCTP VDM or MCU Mailbox interface to reach the Caliptra subsystem.

| Pros | Cons |
|------|------|
| Mature, battle-tested libspdm backend (DMTF reference) | C dependency (libspdm) via FFI — complex build with cmake, openssl/mbedtls |
| Supports SPDM 1.0–1.4 (our responder uses 1.0–1.3) | Ruby dependency (cbor-diag) for manifest encoding |
| Already has DOE + MCTP + NVMe + socket transports | Small community (3 contributors, 18 stars) |
| CLI ready — can issue arbitrary SPDM request sequences | External dependency outside our control |
| Supports certificate retrieval, CSR, set-certificate | Transport integration requires understanding spdm-utils internals |
| Dual-licensed Apache-2.0/MIT (compatible) | Tightly coupled to libspdm version (currently pinned to 3.8.1) |
| Can also serve as QEMU SPDM responder backend | Does not share code with our existing caliptra-util-host |

**Effort**: Medium. Need to implement a new transport module in spdm-utils that bridges to our MCTP/Mailbox driver. Build system integration for libspdm adds complexity.

---

### Option B: Integrate `libspdm` Directly into `caliptra-util-host`

[libspdm](https://github.com/DMTF/libspdm) (DMTF) is the reference C implementation supporting SPDM 1.0–1.4. It provides requester and responder libraries with pluggable crypto (OpenSSL/MbedTLS) and transport backends.

**Approach**: Write Rust FFI bindings for libspdm's requester API and integrate them into caliptra-util-host as a new module, using our existing MCTP VDM transport as the underlying send/receive channel.

| Pros | Cons |
|------|------|
| DMTF reference — maximum spec compliance and interop confidence | Large C codebase (96% C) — FFI maintenance burden |
| Supports SPDM 1.0–1.4 + secured messages | Complex build: cmake + crypto library (OpenSSL or MbedTLS) |
| Active community (62 contributors, 175 stars, 149 forks) | Requires writing and maintaining unsafe Rust FFI bindings |
| Well-documented threat model, design, and user guide | Memory management across FFI boundary needs careful handling |
| Unified with caliptra-util-host — single toolchain for all operations | Increases caliptra-util-host binary size and dependency footprint |
| Reuses our existing transport layer directly | Cross-compilation to different targets may be challenging |
| C binding already exists in caliptra-util-host (cbinding/) | Two crypto stacks (libspdm's + any Rust crypto) to maintain |

**Effort**: High. FFI binding generation, libspdm build integration, transport adapter implementation, and testing against our responder.

---

### Option C: Use `spdm-rs` (Pure Rust) + Custom Transport

[spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs) is a pure Rust implementation of SPDM supporting 1.0–1.4, with MCTP and DOE transports. It provides both requester and responder, supports `no_std`, and uses ring or mbedtls for crypto.

**Approach**: Use the spdm-rs requester library as a dependency, implement a custom transport that routes messages through our MCTP VDM or Mailbox driver, and build a CLI or integrate into caliptra-util-host.

| Pros | Cons |
|------|------|
| Pure Rust — no C/FFI, native cargo build | Smaller community (13 contributors, 53 stars) |
| Supports SPDM 1.0–1.4 + secure sessions | Self-described as "sample code", not production quality yet |
| Both requester and responder in Rust | Less battle-tested than libspdm |
| `no_std` support (could share code with firmware side) | May have spec compliance gaps vs. reference implementation |
| MCTP + DOE transports already implemented | Requires nightly Rust toolchain |
| Async and sync modes available | Fewer crypto algorithm options than libspdm |
| Clean integration into Rust codebase | PQC/advanced features still maturing |
| Cross-tested against libspdm spdm-emu | |
| PQC support (ML-DSA, ML-KEM) via aws-lc-rs | |

**Effort**: Medium. Implement transport adapter, wire into caliptra-util-host or standalone binary. No FFI needed.

---

### SPDM Recommendation Summary

| Criteria | spdm-utils (A) | libspdm Direct (B) | spdm-rs (C) |
|----------|:-:|:-:|:-:|
| Spec compliance | High (libspdm) | High (libspdm) | Medium-High |
| Build complexity | High (cmake+C+Ruby) | High (cmake+C+FFI) | Low (pure Cargo) |
| Integration with caliptra-util-host | Low (separate tool) | High (same library) | High (same library) |
| Maintenance burden | Medium | High (FFI bindings) | Low |
| Language consistency | Mixed (Rust+C) | Mixed (Rust+C) | Pure Rust |
| Community/maturity | Low | High | Medium |
| SPDM version coverage | 1.0–1.4 | 1.0–1.4 | 1.0–1.4 |
| Our responder compatibility | 1.0–1.3 ✓ | 1.0–1.3 ✓ | 1.0–1.3 ✓ |

**Option A (spdm-utils)** is best for quick validation and conformance testing — it's a ready-made CLI. However, it lives outside our codebase and adds a C+Ruby build dependency.

**Option B (libspdm direct)** gives maximum spec confidence but has the highest integration cost due to FFI.

**Option C (spdm-rs)** offers the cleanest integration path for a Rust-native project like ours, with the trade-off of less maturity. Note that spdm-utils itself is just a wrapper around libspdm — if spec compliance is the concern, spdm-rs has been cross-tested against libspdm's spdm-emu.

> **Note**: Options A and B both use the same underlying libspdm. The real decision is between libspdm (via A or B) and spdm-rs (C). A hybrid approach is also possible: use spdm-utils (A) for conformance testing in CI, and spdm-rs (C) for the integrated utility.

---

## 2. PLDM Firmware Update Utility Options

The PLDM utility needs to act as an **update agent (UA)** that can push firmware packages to the Caliptra MCU PLDM firmware device. The update flow involves discovery, component negotiation, firmware data transfer, verification, apply, and activation.

### Option A: Use OpenBMC `libpldm`

[libpldm](https://github.com/openbmc/libpldm) is a C library from OpenBMC that handles encoding/decoding of PLDM messages across all PLDM types (Base, Platform, BIOS, FRU, FwUpdate). It is lightweight, endian-safe, and has no OpenBMC-specific dependencies.

**Approach**: Write Rust FFI bindings for libpldm's firmware update encode/decode functions, and implement the update agent state machine on the Rust side using these primitives for message construction/parsing.

| Pros | Cons |
|------|------|
| Industry standard — used by OpenBMC deployments | C library — requires FFI bindings and build integration (meson) |
| Covers all PLDM types (Base, Platform, FRU, FwUpdate) | Only handles encode/decode — no state machine or orchestration |
| Active maintenance (46 contributors) | We still need to write the entire UA state machine ourselves |
| ABI stability process (stable/testing/deprecated tiers) | Duplicate effort — we already have PLDM message types in caliptra-mcu-pldm-common |
| Zephyr module support | Different build system (meson) from our project (cargo) |
| Well-tested message encoding/decoding | No Rust crate available — would need to create and maintain bindings |
| Apache-2.0 license (compatible) | Our pldm-common already implements the same encode/decode in Rust with zerocopy |

**Effort**: High. FFI binding generation, meson build integration, and we still need to implement the full update agent state machine since libpldm only handles message codec.

---

### Option B: Standalone Executable from `caliptra-mcu-pldm-ua`

The existing `caliptra-mcu-pldm-ua` crate is a complete PLDM update agent with discovery and update state machines, retry logic, component matching, and firmware data streaming. It currently lives in `emulator/bmc/pldm-ua/` and is used as a library.

**Approach**: Add a binary target to `caliptra-mcu-pldm-ua` with a concrete transport implementation (e.g., MCTP over TCP/serial) and a CLI for specifying device address and firmware package path.

| Pros | Cons |
|------|------|
| Complete UA already implemented — discovery + update state machines | Currently library-only, needs a binary entry point |
| Uses our own PLDM types (caliptra-mcu-pldm-common) — zero duplication | Transport trait (PldmSocket) needs a concrete implementation for host use |
| Battle-tested with our firmware device (caliptra-mcu-pldm-lib) | Lives in `emulator/bmc/` — may need to be relocated for host tooling |
| Retry logic, timeouts, component matching already done | Uses std (threads, Arc/Mutex) — not an issue for host utility |
| Integrates with caliptra-mcu-pldm-fw-pkg for package loading | Separate binary from caliptra-util-host commands |
| Minimal new code — just CLI + transport + main() | Not directly callable from caliptra-util-host session API |
| Pure Rust — no FFI | |
| PLDM FwUpdate 1.3.0 protocol support | |

**What needs to be built**:
1. A `src/bin/main.rs` with CLI argument parsing (device address, firmware package path, log level)
2. A concrete `PldmSocket` implementation (e.g., MCTP socket, TCP, or serial)
3. Integration with `caliptra-mcu-pldm-fw-pkg` for loading firmware packages from files

**Effort**: Low-Medium. The core logic exists; we need a transport implementation and CLI wrapper.

---

### Option C: Integrate `caliptra-mcu-pldm-ua` into `caliptra-util-host`

**Approach**: Add `caliptra-mcu-pldm-ua` as a dependency of caliptra-util-host. Implement the `PldmSocket` trait using the existing MCTP VDM transport. Expose PLDM firmware update as a new command set alongside the existing Caliptra commands.

| Pros | Cons |
|------|------|
| Unified tool — one utility for Caliptra commands + PLDM update | Adds PLDM state machine complexity to caliptra-util-host |
| Reuses existing MCTP VDM transport (MctpVdmDriver) | PLDM update is a long-running operation vs. quick Caliptra commands |
| Single session can do attestation + firmware update | Different execution model (state machine + streaming vs. request/response) |
| Consistent user experience across all operations | Larger dependency tree for caliptra-util-host |
| Can be exposed via the C binding (cbinding/) for non-Rust consumers | May complicate the session management (Caliptra session vs. PLDM session) |
| Leverages caliptra-util-host's OSAL for cross-platform support | |
| Pure Rust — no FFI | |

**What needs to be built**:
1. `PldmSocket` adapter that wraps `MctpVdmDriver` or a raw MCTP transport
2. PLDM command module in caliptra-util-host exposing `firmware_update()` API
3. Integration with session management (or a separate PLDM session type)
4. CLI support in the validator/client apps

**Effort**: Medium. Transport adapter + API integration + CLI.

---

### PLDM Recommendation Summary

| Criteria | libpldm (A) | Standalone pldm-ua (B) | Integrated in caliptra-util-host (C) |
|----------|:-:|:-:|:-:|
| Implementation completeness | Codec only | Full UA | Full UA |
| New code required | High (state machine + FFI) | Low (CLI + transport) | Medium (adapter + API) |
| Language consistency | Mixed (Rust+C) | Pure Rust | Pure Rust |
| Reuse of existing code | Low (duplicates pldm-common) | High | High |
| User experience | N/A (library) | Separate binary | Unified with Caliptra cmds |
| Build complexity | High (meson+FFI) | Low | Low |
| Maintenance burden | High | Low | Medium |

**Option A (libpldm)** provides no real advantage — it only handles message encode/decode, which we already have in `caliptra-mcu-pldm-common`. We'd still need to write the entire state machine, making this option strictly inferior.

**Option B (Standalone pldm-ua)** is the fastest path to a working PLDM firmware update tool. The UA is already complete; we just need a transport and CLI.

**Option C (Integrated)** provides the best long-term user experience but requires more integration work to bridge the PLDM UA's execution model with caliptra-util-host's command-oriented architecture.

> A phased approach is possible: start with **Option B** for quick results, then refactor into **Option C** once the transport and CLI patterns are proven.

---

## 4. Transport Considerations

Both SPDM and PLDM utilities need to route messages to the Caliptra subsystem. The firmware responders use MCTP as the transport (SPDM message type 0x5, PLDM message type 0x1). Key considerations:

| Transport Path | SPDM | PLDM | Notes |
|---------------|:----:|:----:|-------|
| MCTP over I3C | ✓ | ✓ | Physical hardware path |
| MCTP over TCP/socket | ✓ | ✓ | Emulator/testing path |
| MCU Mailbox | ✗ | ✗ | Caliptra-specific commands only |
| MCTP VDM (caliptra-util-host) | ✓* | ✓* | If raw MCTP message passthrough is added |
| DOE (PCIe) | ✓ | ✗ | SPDM only, requires PCIe device |

*The existing `MctpVdmDriver` in caliptra-util-host is designed for Caliptra VDM commands. SPDM and PLDM use standard MCTP message types (not VDM). A raw MCTP transport adapter may be needed alongside the VDM transport.

---

## 5. Summary of Recommendations

### SPDM
- **Short-term / CI testing**: Use **spdm-utils (Option A)** as an external conformance test tool (already used in CI via spdm-emu)
- **Integrated utility**: Use **spdm-rs (Option C)** for a Rust-native requester integrated into caliptra-util-host, with a custom transport adapter

### PLDM
- **Start with**: **Standalone pldm-ua binary (Option B)** — lowest effort, fastest path to working firmware update
- **Evolve to**: **Integrated in caliptra-util-host (Option C)** — unified user experience with Caliptra commands

### Shared Work
- Implement a raw **MCTP transport** adapter that both SPDM and PLDM utilities can use to reach the Caliptra subsystem
- This transport should support both physical (I3C) and emulated (TCP socket) paths
