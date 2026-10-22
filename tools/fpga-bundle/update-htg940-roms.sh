#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "Usage: $0 <core-rom.bin> <mcu-rom.bin> <output.bit> [helper-dir]" >&2
    exit 2
fi

helper_dir="${4:-/mnt/c/Users/marcovisaya/OneDrive - Microsoft/Desktop/htg940/marco}"
for command in powershell.exe wslpath; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "ERROR: Required WSL command is not installed: $command" >&2
        exit 2
    }
done

base_bit="$helper_dir/htg940_board_top_20261022_1304.bit"
memory_map="$helper_dir/htg940_board_top_20261022_1304.mmi"
updater="$helper_dir/update-htg940-roms.ps1"
for input in "$1" "$2" "$base_bit" "$memory_map" "$updater"; do
    [[ -s "$input" ]] || {
        echo "ERROR: Missing or empty input: $input" >&2
        exit 2
    }
done

powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "$(wslpath -w "$updater")" \
    -CoreRom "$(wslpath -w "$(realpath -- "$1")")" \
    -McuRom "$(wslpath -w "$(realpath -- "$2")")" \
    -OutputBitstream "$(wslpath -w "$(realpath -m -- "$3")")" \
    -BaseBitstream "$(wslpath -w "$base_bit")" \
    -MemoryMap "$(wslpath -w "$memory_map")"
