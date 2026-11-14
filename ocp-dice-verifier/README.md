# OCP DICE Verifier Workspace

This workspace houses the host-side verification libraries, plugins, and tools for authenticating DICE-based certificate chains and appraising attestation evidence for Caliptra and OCP DPE iRoT profiles.

## Scope & Implementation Status

| Capability / Component | Description | Status |
| :--- | :--- | :--- |
| **TCG DICE Certificate Evidence Decoder (`dice-rs`)** | Parsing and extraction of `TcbInfo`, `MultiTcbInfo`, `Ueid`, and DICE Key Purpose OIDs from X.509 certs. | **Implemented** |
| **DMTF SPDM Certificate Extensions (`spdm-cert-rs`)** | Decoding SPDM certificate chains (GET_CERTIFICATE responses / raw DER) and DSP0274 extensions (`id-DMTF-spdm-extension`, `id-DMTF-hardware-identity`, `id-DMTF-mutable-certificate`). | **Implemented** |
| **Interactive DICE Chain Visualizer (`dice-visualizer-wasm`)** | Client-side WebAssembly parser and tabbed certificate explorer with Mermaid trust graph and TCG-compliant DICE tables. | **Implemented** |
| **Trust Anchor Store & Path Validation** | Validating certificate chain signatures and path against trusted root CAs. | **TBD** |
| **Reference Value Ingestion** | Ingesting and matching golden measurements from CoRIM/CoMID manifests (via `corim-rs`). | **TBD** |
| **OCP DPE Attestation Engine (`ocp-dpe-appraisal`)** | Appraising Caliptra RoT (FMC, RT) & DPE Leaf measurements against reference values; Veraison-compliant architecture. | **TBD** |
| **CLI Verification Tool (`ocpdice`)** | Command-line tool for inspecting DICE certificate chains and appraising evidence (matching `ocptoken`). | **TBD** |

## Workspace Architecture

Following Clean Architecture, the workspace decouples spec format decoders from platform appraisal rules:

```text
ocp-dice-verifier/
├── Cargo.toml                  # Independent host workspace (std)
└── crates/
    ├── dice-rs/                # TCG DICE Attestation Architecture decoder (TCG v1.1, v1.2+)
    ├── spdm-cert-rs/           # DMTF DSP0274 SPDM certificate extensions decoder
    ├── dice-visualizer-wasm/   # Client-side WASM visualizer & web explorer
    └── ocp-dpe-appraisal/      # OCP DPE appraisal engine (planned)
```

### Components

1. **`dice-rs` (TCG DICE Spec Crate)**
   - Pure Rust implementation of TCG DICE Attestation Architecture specifications.
   - Decodes `TcbInfo`, `MultiTcbInfo`, `Ueid`, and DICE Key Purposes according to the TCG DICE specification.
   - Clean, standalone library with zero SPDM or platform-specific baggage; compatible with Veraison DICE models.

2. **`spdm-cert-rs` (DMTF SPDM Cert Spec Crate)**
   - Parses SPDM certificate chains (both SPDM GET_CERTIFICATE response payloads and raw concatenated DER).
   - Decodes DMTF SPDM v1.3.0 (DSP0274) certificate extensions (`id-DMTF-spdm-extension`, `id-DMTF-hardware-identity`, `id-DMTF-mutable-certificate`, `id-DMTF-device-info`).

3. **`dice-visualizer-wasm` (Interactive WASM Visualizer)**
   - WebAssembly-compiled certificate inspector providing interactive SVG trust graph visualization and per-certificate TCG DICE / SPDM tab inspection in zero-installation static HTML/JS.

4. **`ocp-dpe-appraisal` (OCP DPE Attestation Engine - Planned)**
   - Composes `dice-rs` and `spdm-cert-rs`.
   - Evaluates Caliptra certificate chains (IDevID -> LDevID -> FMC -> RT -> DPE Leaf) against OCP DPE iRoT profile requirements.
   - Appraises DICE measurements against CoRIM/CoMID reference values.
   - Designed to be Veraison-compliant so it can readily be integrated as an external Veraison scheme plugin if desired.

## Building & Running

### 1. Running Workspace Tests

```bash
cd ocp-dice-verifier
cargo test
```

### 2. Building the WebAssembly Visualizer

**Prerequisites:**
```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

**Compile WASM and Generate JS Bindings:**
```bash
cd ocp-dice-verifier
cargo build --target wasm32-unknown-unknown --release -p dice-visualizer-wasm
wasm-bindgen target/wasm32-unknown-unknown/release/dice_visualizer_wasm.wasm \
  --out-dir crates/dice-visualizer-wasm/web/pkg \
  --target web --no-typescript
```

### 3. Running the Visualizer Locally

Serve the static web app using any local HTTP server:
```bash
cd crates/dice-visualizer-wasm/web
python3 -m http.server 8080
```
Then open `http://localhost:8080` in your browser.

## License

Licensed under the Apache License, Version 2.0 (Apache-2.0).
