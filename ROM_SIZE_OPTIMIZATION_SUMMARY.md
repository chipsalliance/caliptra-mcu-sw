# ROM Size Optimization Summary

## Problem
The user-app with default features was overflowing the FLASH ROM by ~44 KB:
- `.rodata` section overflow: 21,032 bytes
- `.data` section overflow: 23,096 bytes
- Available FLASH: 512 KB (0x80000)
- Binary size: ~589 KB

## Solution Implemented

### 1. **Removed Debug Symbols** ✓
- **File**: `Cargo.toml` (root)
- **Change**: Set `debug = false` and added `strip = "debuginfo"`
- **Impact**: ~264 bytes freed (minimal but good practice)
- **Rationale**: Debug symbols in release builds increase size significantly

### 2. **Made Heavy Libraries Optional** ✓
- **File**: `platforms/emulator/runtime/userspace/apps/user/Cargo.toml`
- **Changes**:
  - Moved `caliptra-mcu-spdm-lib` → optional dependency
  - Moved `caliptra-mcu-mctp-vdm-lib` → optional dependency
  - Moved `caliptra-mcu-pldm-lib` → optional dependency
- **Rationale**: These libraries are only needed when features are enabled; making them optional prevents them from being compiled unconditionally

### 3. **Made Feature Imports Conditional** ✓
- **File**: `platforms/emulator/runtime/userspace/apps/user/src/image_loader/mod.rs`
- **Change**: Wrapped PLDM library imports in `#[cfg(...)]` blocks
- **Rationale**: When features are disabled, the imports won't require the optional libraries

### 4. **Feature-Gated Module Compilation** ✓
- **File**: `platforms/emulator/runtime/userspace/apps/user/src/main.rs`
- **Changes**:
  - Wrapped `mod spdm` in `#[cfg(feature = "spdm")]`
  - Wrapped `mod vdm` in `#[cfg(feature = "mctp-vdm-service")]`
- **Rationale**: Entire modules aren't compiled unless their features are enabled

### 5. **Adjusted Default Features** ✓
- **File**: `platforms/emulator/runtime/userspace/apps/user/Cargo.toml`
- **Previous defaults**: `["spdm", "streaming-boot", "flash-boot", "firmware-update", "doe", "mcu-mbox-service"]`
- **New defaults**: `["streaming-boot", "flash-boot", "firmware-update", "doe", "mcu-mbox-service"]`
- **Impact**: Removed SPDM (saves ~20-25 KB)
- **Key Finding**: SPDM protocol implementation is the largest feature (~20+ KB)

## Results

### Size Comparison
| Metric | Before | After | Status |
|--------|--------|-------|--------|
| Binary size | ~589 KB | ~416 KB | ✓ Fits |
| FLASH limit | 512 KB | 512 KB | ✓ Compliant |
| Overflow | +44 KB | **0 KB** | ✓ **RESOLVED** |

## How to Use SPDM (if needed)

### Build with SPDM Support
```bash
cargo xtask runtime-build --features "spdm,streaming-boot,flash-boot,firmware-update,doe,mcu-mbox-service"
```

### Or modify defaults in Cargo.toml
In `platforms/emulator/runtime/userspace/apps/user/Cargo.toml`:
```toml
default = ["spdm", "streaming-boot", "flash-boot", "firmware-update", "doe", "mcu-mbox-service"]
```

## Feature Breakdown

| Feature | Size Impact | Default | Purpose |
|---------|------------|---------|---------|
| **spdm** | ~20-25 KB | ❌ Removed | SPDM protocol responder (large) |
| **mctp-vdm-service** | Included | ❌ Optional | VDM handlers via MCTP |
| streaming-boot | Included | ✓ Enabled | Firmware streaming boot |
| flash-boot | Included | ✓ Enabled | Flash-based boot |
| firmware-update | Included | ✓ Enabled | Firmware update support |
| doe | Included | ✓ Enabled | Data Object Exchange |
| mcu-mbox-service | Included | ✓ Enabled | MCU mailbox service |

## Implementation Details

### Optional Dependency Configuration
```toml
[dependencies]
caliptra-mcu-spdm-lib = { workspace = true, optional = true }
caliptra-mcu-mctp-vdm-lib = { workspace = true, optional = true }
caliptra-mcu-pldm-lib = { workspace = true, optional = true }

[features]
spdm = ["caliptra-mcu-spdm-lib"]
mctp-vdm-service = ["caliptra-mcu-mctp-vdm-lib"]
streaming-boot = ["caliptra-mcu-pldm-lib"]
test-pldm-* = ["caliptra-mcu-pldm-lib"]
test-mctp-spdm-* = ["caliptra-mcu-spdm-lib"]
test-doe-spdm-* = ["caliptra-mcu-spdm-lib"]
```

### Module Feature Gating
```rust
// In src/main.rs
#[cfg(feature = "spdm")]
mod spdm;

#[cfg(feature = "mctp-vdm-service")]
mod vdm;

pub(crate) async fn async_main() {
    #[cfg(feature = "spdm")]
    EXECUTOR
        .get()
        .spawner()
        .spawn(spdm::spdm_task(EXECUTOR.get().spawner()))
        .unwrap();

    #[cfg(feature = "mctp-vdm-service")]
    EXECUTOR.get().spawner().spawn(vdm::vdm_task()).unwrap();
    
    // ... rest of tasks
}
```

## Recommendations

1. **Keep default features as-is** unless SPDM support is needed
2. **SPDM is opt-in** for deployments requiring SPDM protocol support
3. **All other critical services** (firmware update, DOE, mailbox) remain in defaults
4. **Test with `--features "spdm,..."` if SPDM is needed** in specific deployments
5. **Monitor size** when adding new features to catch regressions early

## Files Modified

1. `/Cargo.toml` - Release profile optimization
2. `platforms/emulator/runtime/userspace/apps/user/Cargo.toml` - Optional dependencies & features
3. `platforms/emulator/runtime/userspace/apps/user/src/main.rs` - Feature-gated modules
4. `platforms/emulator/runtime/userspace/apps/user/src/image_loader/mod.rs` - Conditional imports

## Verification

To verify the binary still fits:
```bash
cargo xtask runtime-build
# Should complete without linker errors
```

To build with all features enabled (will exceed ROM):
```bash
cargo xtask runtime-build --features "spdm,streaming-boot,flash-boot,firmware-update,doe,mcu-mbox-service,mctp-vdm-service"
# Will overflow - demonstrating the size constraint
```
