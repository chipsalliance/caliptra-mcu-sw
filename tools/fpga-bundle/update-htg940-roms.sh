#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/bundle-common.sh"

usage() {
    echo "Usage: $0 CORE.bin MCU.bin OUTPUT.bit [HELPER_DIR] [--base-bitstream BIT] [--memory-map MMI] [--validate-only]"
}
(( $# >= 3 )) || { usage >&2; exit 2; }
core_rom="$1"; mcu_rom="$2"; output="$3"; shift 3
helper_dir="$default_helper_dir"
if (( $# )) && [[ "$1" != --* ]]; then helper_dir="$1"; shift; fi
base_bit=""
memory_map=""
validate_only=false
while (( $# )); do
    case "$1" in
        --base-bitstream|--memory-map)
            (( $# >= 2 )) || fail "$1 requires a path"
            if [[ "$1" == --base-bitstream ]]; then base_bit="$2"; else memory_map="$2"; fi
            shift 2 ;;
        --validate-only) validate_only=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
helper_dir="$(realpath -- "$helper_dir")"
base_bit="${base_bit:-$helper_dir/htg940_board_top_forced_ulpi.bit}"
memory_map="${memory_map:-$helper_dir/htg940_board_top_forced_ulpi.mmi}"
for input in "$core_rom" "$mcu_rom" "$base_bit" "$memory_map"; do require_file "$input"; done
core_rom="$(realpath -- "$core_rom")"
mcu_rom="$(realpath -- "$mcu_rom")"
base_bit="$(realpath -- "$base_bit")"
memory_map="$(realpath -- "$memory_map")"
output="$(realpath -m -- "$output")"
[[ "$output" == *.bit ]] || fail "Output must have a .bit extension"
[[ ! -e "$output" && ! -L "$output" && ! -e "$output.json" ]] || fail "Output or provenance report already exists: $output"
[[ "$output" != "$base_bit" && "$output" != "$memory_map" && "$output" != "$core_rom" && "$output" != "$mcu_rom" ]] ||
    fail "Output aliases an input"
mkdir -p -- "$(dirname -- "$output")"
require_file "$helper_dir/htg940_update_roms.py"
require_tools python3
python3 "$helper_dir/htg940_update_roms.py" --bit "$base_bit" --mmi "$memory_map" \
    --core-rom "$core_rom" --mcu-rom "$mcu_rom" --out "$output" --dry-run
if [[ "$validate_only" == true ]]; then exit 0; fi
require_tools powershell.exe wslpath
require_file "$helper_dir/update-htg940-roms.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "$(wslpath -w "$helper_dir/update-htg940-roms.ps1")" \
    -CoreRom "$(wslpath -w "$core_rom")" -McuRom "$(wslpath -w "$mcu_rom")" \
    -OutputBitstream "$(wslpath -w "$output")" \
    -BaseBitstream "$(wslpath -w "$base_bit")" -MemoryMap "$(wslpath -w "$memory_map")"
require_file "$output"
require_file "$output.json"
echo "Repacked bitstream: $output"
