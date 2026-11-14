#!/usr/bin/env bash
# Licensed under the Apache-2.0 license

bundle_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bundle_mcu_repo="$(cd -- "$bundle_script_dir/../.." && pwd)"
default_build_dir="$bundle_mcu_repo/target/htg940-fpga"
default_bundle="$bundle_mcu_repo/target/htg940-fpga-test-bundle.zip"
default_helper_dir="/mnt/c/Users/marcovisaya/OneDrive - Microsoft/Desktop/htg940/marco"
default_recovery_dir="$default_helper_dir/htg940-fpga-test-bundle-working/usb-recovery-python"
bundle_files=(
    caliptra_rom.bin mcu_rom.bin caliptra_fw.bin soc_manifest.bin mcu_runtime.bin
    hardware-provenance.txt mcu-rom-provenance.txt BUNDLE_INFO.txt
)

fail() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -s "$1" ]] || fail "Missing or empty file: $1"; }
require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || fail "Required command is not installed: $tool"
    done
}

cleanup_bundle_stage() {
    local directory="$1" name
    for name in "${bundle_files[@]}" SHA384SUMS bundle.zip; do
        rm -f -- "$directory/$name"
    done
    rmdir -- "$directory"
}

verify_roms() {
    local directory="$1" core_size mcu_size expected actual
    core_size="$(wc -c <"$directory/caliptra_rom.bin")"
    mcu_size="$(wc -c <"$directory/mcu_rom.bin")"
    (( core_size > 0 && core_size <= 98304 )) || fail "Caliptra ROM must fit the 96-KiB HTG ROM"
    (( mcu_size == 131072 )) || fail "MCU ROM must be the complete 128-KiB image, including its digest"
    expected="$(tail -c 48 "$directory/mcu_rom.bin" | od -An -v -tx1 | tr -d ' \n')"
    actual="$(head -c 131024 "$directory/mcu_rom.bin" | sha384sum)"
    [[ "${actual%% *}" == "$expected" ]] || fail "MCU ROM trailing SHA-384 digest is invalid"
}

verify_bundle() {
    local archive="$1" directory="$2" name digest filename extra
    local -a entries
    local -A remaining=()
    require_file "$archive"
    mapfile -t entries < <(unzip -Z1 "$archive")
    (( ${#entries[@]} == ${#bundle_files[@]} + 1 )) || fail "Unexpected bundle file list"
    for name in "${bundle_files[@]}" SHA384SUMS; do
        remaining["$name"]=1
    done
    for name in "${entries[@]}"; do
        [[ -n "${remaining[$name]+present}" ]] || fail "Unexpected or duplicate bundle member: $name"
        unset 'remaining[$name]'
    done
    unzip -q "$archive" "${bundle_files[@]}" SHA384SUMS -d "$directory"
    for name in "${bundle_files[@]}"; do
        require_file "$directory/$name"
        remaining["$name"]=1
    done
    while read -r digest filename extra; do
        [[ "$digest" =~ ^[0-9a-fA-F]{96}$ && -z "${extra:-}" ]] || fail "Malformed SHA384SUMS entry"
        [[ -n "${remaining[$filename]+present}" ]] || fail "Unexpected or duplicate checksum: $filename"
        unset 'remaining[$filename]'
    done <"$directory/SHA384SUMS"
    (( ${#remaining[@]} == 0 )) || fail "SHA384SUMS does not cover every required file"
    (cd "$directory" && sha384sum -c SHA384SUMS)
    grep -qx 'format_version=2' "$directory/BUNDLE_INFO.txt" || fail "Unsupported bundle format; rebuild with these helpers"
    grep -qx 'mcu_rom_feature=htg940' "$directory/BUNDLE_INFO.txt" || fail "Bundle is not an HTG recovery build"
    verify_roms "$directory"
}
