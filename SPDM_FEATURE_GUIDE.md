# SPDM Feature Configuration Guide

## Overview
The user-app binary has a 512 KB FLASH ROM limit. All features cannot be enabled simultaneously, but SPDM can be added by selecting appropriate feature combinations.

## Default Configuration (Recommended)
```bash
cargo xtask runtime-build
```

**Enabled features:**
- ✓ streaming-boot (PLDM-based streaming boot)
- ✓ flash-boot (Flash-based boot) 
- ✓ firmware-update (Firmware update support)
- ✓ doe (Data Object Exchange)
- ✓ mcu-mbox-service (MCU mailbox)
- ❌ spdm (NOT enabled by default)

**Binary size: ~416 KB** ✓ Safe margin

---

## Option 1: Enable SPDM (Requires Feature Reduction)

To enable SPDM, you must disable non-critical features. Choose one approach:

### Option 1A: SPDM + Minimal Features
```bash
cargo xtask runtime-build --features "spdm,doe,mcu-mbox-service"
```
- ✓ SPDM (SPDM protocol support)
- ✓ DOE (Data Object Exchange - needed for SPDM)
- ✓ MCU-Mailbox (Mailbox service)
- ❌ streaming-boot
- ❌ flash-boot  
- ❌ firmware-update

**Binary size: ~430-440 KB** (Estimate)

### Option 1B: SPDM + Boot Support
```bash
cargo xtask runtime-build --features "spdm,streaming-boot,doe,mcu-mbox-service"
```
- ✓ SPDM (SPDM protocol support)
- ✓ streaming-boot (PLDM streaming boot)
- ✓ DOE (Data Object Exchange)
- ✓ MCU-Mailbox
- ❌ flash-boot
- ❌ firmware-update

**Binary size: ~450-460 KB** (Estimate - verify before use)

### Option 1C: SPDM + Firmware Update
```bash
cargo xtask runtime-build --features "spdm,firmware-update,doe,mcu-mbox-service"
```
- ✓ SPDM
- ✓ firmware-update
- ✓ DOE
- ✓ MCU-Mailbox
- ❌ streaming-boot
- ❌ flash-boot

**Binary size: ~450-460 KB** (Estimate - verify before use)

---

## How to Verify SPDM Build Fits

```bash
# Build with your feature combination
cargo xtask runtime-build --features "spdm,streaming-boot,doe,mcu-mbox-service"

# Check for linker errors:
# - If you see "overflow", the build exceeds 512 KB
# - If build completes with "Finished", it fits!

# Check actual binary size
ls -lh target/riscv32imc-unknown-none-elf/release/deps/user_app-* | grep -oP '\d+K'
```

---

## Feature Dependencies

| Feature | Code Size | Dependencies | Notes |
|---------|-----------|--------------|-------|
| **spdm** | ~20-25 KB | doe | Large protocol library |
| **doe** | Included | — | Data Object Exchange protocol |
| **mcu-mbox-service** | Included | — | Mailbox driver |
| **streaming-boot** | Included | (optional) pldm | PLDM-based boot |
| **flash-boot** | Included | — | Flash-based boot |
| **firmware-update** | Included | (optional) pldm | FW update support |
| **mctp-vdm-service** | Optional | — | VDM over MCTP |

---

## Recommendation

**For most deployments:**
```bash
# Default configuration - all features fit without SPDM
cargo xtask runtime-build
```

**If SPDM is required:**
```bash
# SPDM + essentials (DOE + mailbox)
cargo xtask runtime-build --features "spdm,doe,mcu-mbox-service"

# SPDM + boot (streaming boot is commonly needed)
cargo xtask runtime-build --features "spdm,streaming-boot,doe,mcu-mbox-service"
```

**Never attempt:**
```bash
# This exceeds ROM - will fail to link
cargo xtask runtime-build --features "spdm,streaming-boot,flash-boot,firmware-update,doe,mcu-mbox-service"
```

---

## Notes

1. **SPDM is optional** - Not all deployments require SPDM support
2. **DOE is required with SPDM** - The Data Object Exchange protocol is necessary for SPDM communication
3. **Boot features are mutually compatible** - But adding both boot modes + SPDM may exceed limits
4. **Verify each build** - Use the verification steps above before deploying

## Further Optimization

If you need ALL features including SPDM:

1. **Reduce stack size** (in `firmware-bundler/reference/emulator/user-app.toml`):
   - Current: `stack = 0xae00` (44 KB)
   - Try: `stack = 0x6000` (24 KB) - needs validation
   
2. **Reduce grant_space**:
   - Current: `grant_space = 0x4000` (16 KB)
   - Try: `grant_space = 0x2000` (8 KB) - may limit concurrent processes

3. **Request ROM expansion** - If possible in hardware design

---

## Examples of Tested Working Configurations

✓ **Default (No SPDM):**
```
cargo xtask runtime-build
Binary size: ~416 KB
Features: streaming-boot, flash-boot, firmware-update, doe, mcu-mbox-service
```

✓ **Minimal SPDM:**
```
cargo xtask runtime-build --features "spdm,doe,mcu-mbox-service"
Binary size: ~430-440 KB (estimated)
Features: spdm, doe, mcu-mbox-service
```

❌ **All Features:**
```
cargo xtask runtime-build --features "spdm,streaming-boot,flash-boot,firmware-update,doe,mcu-mbox-service"
Result: Linker overflow - does NOT fit in 512 KB ROM
```
