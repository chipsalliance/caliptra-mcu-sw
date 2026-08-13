# Caliptra SPDM VDM Client

Command-line tool for validating Caliptra VDM (Vendor-Defined Message) commands
over SPDM/MCTP transport. Can be used standalone for manual testing or spawned
automatically by the integration test harness.

## Architecture

```
┌────────────────────────────┐              ┌──────────────────────┐              ┌────────────────┐
│  caliptra-spdm-validator   │  TCP socket  │  SpdmValidatorRunner │  I3C/MCTP   │  MCU Responder │
│  (this binary)             │◄────────────►│  (bridge)            │◄────────────►│  (emulator)    │
└────────────────────────────┘              └──────────────────────┘              └────────────────┘
          │                                                                              │
          │ uses                                                                         │
          ▼                                                                              ▼
   caliptra-spdm-requester (lib)                                           spdm-lib VDM handler
   transport/spdm_vdm (Transport impl)                                     caliptra-common-commands
```

### Crate Roles

| Crate | Role |
|-------|------|
| `caliptra-mcu-core-util-host-transport` | Transport trait + implementations (Mailbox, MCTP VDM, SPDM VDM). The `spdm_vdm` module provides command codes, wire format, `SpdmVdmDriver` trait, and command dispatch |
| `caliptra-spdm-requester` | Reusable SPDM requester library wrapping libspdm FFI. Implements `SpdmVdmDriver` trait. Pure Rust — no native linking |
| `caliptra-spdm-vdm-client` | This crate (lib + binary). Library exposes `config`, `validator` modules. Binary (`caliptra-spdm-validator`) owns libspdm native linking via `build.rs` |

## Usage

### Standalone (manual testing)

```bash
# Build libspdm first (see "Building libspdm" below), then:
cd caliptra-util-host
LIBSPDM_LIB_DIR=$PWD/target/libspdm-lib cargo build -p caliptra-spdm-vdm-client
```

The validator connects to an SPDM bridge (e.g., `SpdmValidatorRunner`) that
translates TCP socket framing to I3C/MCTP transport toward the MCU responder.
The bridge must already be running before launching the validator.

```bash
# Example: validate ExportAttestedCsr for key IDs 1, 2, 3 using EccP384
./target/debug/caliptra-spdm-validator \
    --server 127.0.0.1:2323 \
    --key-ids 1,2,3 \
    --algorithm 1

# Or use a TOML config file instead of CLI args
./target/debug/caliptra-spdm-validator --config test-config.toml
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--server` | `127.0.0.1:2323` | Bridge address (host:port) |
| `--slot-id` | `0` | SPDM slot ID |
| `--key-ids` | `0,1,2` | Comma-separated key IDs for ExportAttestedCsr |
| `--algorithm` | `1` | Algorithm ID (1=EccP384, 2=MlDsa87), applied to ExportAttestedCsr and GetAttestation |
| `--config` | — | Path to a TOML config file (overrides other args) |

### TOML Configuration

Instead of CLI args, you can use a config file (see `test-config.toml`):

```toml
[network]
server_address = "127.0.0.1:2323"

[spdm]
slot_id = 0

[export_attested_csr]
key_ids = [1, 2, 3]
algorithm = 1

[get_attestation]
algorithm = 1
# Optional 32-byte hex nonce; omit for a fixed test pattern.
# nonce = "a5a5...a5"
```

### GET_ATTESTATION validation

The validator does not hardcode which evidence formats to request. It first
issues a `GET_ATTESTATION` discovery query (`evidence_format = 0`), whose
response carries a supported-format bitmap, then requests evidence for every
format the device advertises. This keeps the test aligned with the firmware's
compile-time feature selection (e.g., a build without `pcr-quote` advertises
only OCP EAT) instead of failing on a differently-configured build.

Checks performed:

- the discovery query returns a well-formed, non-empty bitmap
- every advertised format returns non-empty evidence, with the format echoed
  back in the response
- a format the device did **not** advertise is rejected rather than answered

Cryptographic verification of the evidence (COSE_Sign1 envelope over the OCP
EAT, PCR quote structure and signature, nonce freshness) is not yet performed
and is tracked as a TODO in `src/validator.rs`.

## Integration Tests

The validator is automatically spawned by the integration test harness:

```
tests/integration/src/test_caliptra_util_host_spdm_vdm_validator.rs
```

### Running integration tests

```bash
# 1. Build everything
LIBSPDM_LIB_DIR=$PWD/caliptra-util-host/target/libspdm-lib cargo xtask all-build

# 2. Run the SPDM VDM test
LIBSPDM_LIB_DIR=$PWD/caliptra-util-host/target/libspdm-lib \
cargo test -p caliptra-mcu-tests-integration --lib \
    test_caliptra_util_host_spdm_vdm_validator::test::test_caliptra_util_host_spdm_vdm_validator \
    -- --nocapture --include-ignored
```

### Test flow

1. Integration test boots the MCU HW model (emulator) with I3C + SPDM responder
2. An `SpdmValidatorRunner` bridge is started on a random TCP port — it translates
   between the TCP socket framing and I3C/MCTP transport to the MCU
3. This validator binary is spawned as a subprocess connecting to the bridge
4. The validator establishes an SPDM session and runs VDM commands
5. Results are reported; the bridge exits on STOP command

## Building libspdm

The validator links against libspdm static libraries. Pre-build them once:

```bash
cd caliptra-util-host
cargo fetch   # pulls SPDM-Utils git dependency

SPDM_UTILS_DIR=$(find ~/.cargo/git/checkouts -maxdepth 3 \
    -name "Cargo.toml" -path "*spdm-utils*" -exec dirname {} \; | head -1)

mkdir -p target/libspdm-build && cd target/libspdm-build
cmake \
    -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug \
    -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 \
    -DCOMPILED_LIBCRYPTO_PATH=/usr/lib/ \
    -DCOMPILED_LIBSSL_PATH=/usr/lib/ \
    -DDISABLE_TESTS=1 \
    -DCMAKE_C_FLAGS="-DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 \
        -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 \
        -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1 \
        -DLIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP=0 \
        -DLIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP=0" \
    "${SPDM_UTILS_DIR}/third-party/libspdm"
make -j$(nproc)

mkdir -p ../libspdm-lib
find lib -name "*.a" -exec cp {} ../libspdm-lib/ \;
```

Then build with:

```bash
LIBSPDM_LIB_DIR=$PWD/target/libspdm-lib cargo build -p caliptra-spdm-vdm-client
```
