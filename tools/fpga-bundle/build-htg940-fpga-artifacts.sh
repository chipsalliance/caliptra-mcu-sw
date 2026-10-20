#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: build-htg940-fpga-artifacts.sh [options]

Build the five binary artifacts used by the HTG940 USB recovery test.

Options:
  --mcu-repo PATH       Caliptra MCU workspace
  --caliptra-repo PATH  Caliptra core workspace
  -h, --help            Show this help
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mcu_repo="$(cd -- "$script_dir/../.." && pwd)"
caliptra_repo="$mcu_repo/caliptra-sw"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mcu-repo)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            mcu_repo="$2"
            shift 2
            ;;
        --caliptra-repo)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            caliptra_repo="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

for command in cargo rm sed sha384sum unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "ERROR: Required command is not installed: $command" >&2
        exit 2
    }
done

mcu_repo="$(realpath -- "$mcu_repo")"
caliptra_repo="$(realpath -- "$caliptra_repo")"
[[ -f "$mcu_repo/Cargo.toml" ]] || {
    echo "ERROR: MCU workspace does not contain Cargo.toml: $mcu_repo" >&2
    exit 2
}
[[ -f "$caliptra_repo/Cargo.toml" ]] || {
    echo "ERROR: Caliptra workspace does not contain Cargo.toml: $caliptra_repo" >&2
    exit 2
}

caliptra_rom="$caliptra_repo/target/riscv32imc-unknown-none-elf/firmware/caliptra-fpga-rom.bin"
mcu_rom="$mcu_repo/target/riscv32imc-unknown-none-elf/release/caliptra-mcu-rom-fpga-test-lpcip-usb-ocp-recovery.bin"
recovery_zip="$mcu_repo/target/usb-recovery-minimal.zip"

echo "Building Caliptra FPGA ROM"
(
    cd "$caliptra_repo"
    cargo run --release -p caliptra-builder -- \
        --rom-fpga-with-log \
        "$caliptra_rom"
)

echo "Building MCU FPGA USB recovery ROM"
(
    cd "$mcu_repo"
    # ROM dynamic sizing also builds runtime apps. Do not reuse generated
    # configs from another build; all-build regenerates this pair below.
    echo "Clearing generated attestation/SoC image configs before ROM sizing"
    rm -f -- \
        "$mcu_repo/target/generated/attestation_manifest.toml" \
        "$mcu_repo/target/generated/soc_image_descriptors.toml"
    cargo xtask rom-build \
        --platform fpga \
        --features test-lpcip-usb-ocp-recovery
)

echo "Building Caliptra FMC/runtime, SoC manifest, and MCU runtime"
(
    cd "$mcu_repo"
    cargo xtask all-build \
        --platform fpga \
        --output "$recovery_zip"
)

for artifact in "$caliptra_rom" "$mcu_rom" "$recovery_zip"; do
    [[ -s "$artifact" ]] || {
        echo "ERROR: Build did not produce a nonempty artifact: $artifact" >&2
        exit 1
    }
done

for artifact in caliptra_fw.bin soc_manifest.bin mcu_runtime.bin; do
    unzip -p "$recovery_zip" "$artifact" | sha384sum | \
        sed "s#  -#  $recovery_zip:$artifact#"
done
sha384sum "$caliptra_rom" "$mcu_rom"

echo "FPGA artifacts built successfully."
echo "Caliptra ROM: $caliptra_rom"
echo "MCU ROM: $mcu_rom"
echo "Recovery artifacts: $recovery_zip"