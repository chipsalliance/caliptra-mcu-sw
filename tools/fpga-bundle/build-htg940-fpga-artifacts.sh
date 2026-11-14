#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/bundle-common.sh"

usage() {
    echo "Usage: $0 [--mcu-repo PATH] [--output-dir PATH] [--mcu-rom-only]"
    echo "Build latest HTG recovery images through the MCU workspace and its pinned Core."
}
mcu_repo="$bundle_mcu_repo"
output_dir=""
mcu_rom_only=false
while (( $# )); do
    case "$1" in
        --mcu-repo|--output-dir)
            (( $# >= 2 )) || fail "$1 requires a path"
            if [[ "$1" == --mcu-repo ]]; then mcu_repo="$2"; else output_dir="$2"; fi
            shift 2 ;;
        --mcu-rom-only) mcu_rom_only=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unsupported argument: $1 (separate Core builds and compliance ROMs are not used by this workflow)" ;;
    esac
done
require_tools cargo git unzip cp sha384sum
mcu_repo="$(realpath -- "$mcu_repo")"
require_file "$mcu_repo/core/versions.toml"
output_dir="${output_dir:-$mcu_repo/target/htg940-fpga}"
mkdir -p -- "$output_dir"
output_dir="$(realpath -- "$output_dir")"
export CALIPTRA_HW_REV=latest
export CALIPTRA_MCU_FUSES_HJSON="$mcu_repo/hw/latest/fuses.hjson"
export CALIPTRA_MCU_OTP_MMAP_HJSON="$mcu_repo/hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
cd "$mcu_repo"
cargo xtask switch-version latest
export CALIPTRA_SW_REVISION
CALIPTRA_SW_REVISION="$(git -C core/caliptra-sw rev-parse HEAD)"

if [[ "$mcu_rom_only" == true ]]; then
    cargo xtask rom-build --platform fpga --features htg940
else
    cargo xtask all-build --platform fpga --rom-features htg940 \
        --mcu_cfg mcu,0x0,0xB00C0000,2,2,2,none --separate-runtimes \
        --output "$output_dir/recovery-images.zip"
    unzip -oq "$output_dir/recovery-images.zip" \
        caliptra_rom.bin caliptra_fw.bin soc_manifest.bin mcu_runtime.bin \
        hardware-provenance.txt -d "$output_dir"
fi

mcu_rom="$mcu_repo/target/riscv32imc-unknown-none-elf/release/latest-caliptra-mcu-rom-fpga-htg940.bin"
require_file "$mcu_rom"
require_file "$mcu_rom.provenance.txt"
cp -- "$mcu_rom" "$output_dir/mcu_rom.bin"
cp -- "$mcu_rom.provenance.txt" "$output_dir/mcu-rom-provenance.txt"
if [[ "$mcu_rom_only" == false ]]; then verify_roms "$output_dir"; fi
sha384sum "$output_dir/mcu_rom.bin"
echo "HTG artifacts: $output_dir"
if [[ "$mcu_rom_only" == true ]]; then
    echo "Only MCU ROM was rebuilt; existing Core ROM and recovery images were retained."
fi
