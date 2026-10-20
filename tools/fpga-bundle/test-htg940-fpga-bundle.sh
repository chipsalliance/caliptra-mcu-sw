#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: test-htg940-fpga-bundle.sh <bundle.zip> [options]

Verify an FPGA test bundle, insert its ROMs into a new HTG940 bitstream,
program the FPGA, and run USB recovery with the bundled firmware.

Options:
  --helper-dir PATH       Directory containing the HTG940 helper scripts
  --output-bitstream PATH Generated bitstream path (default: beside bundle)
  --probes PATH           Vivado probes file (default: helper-dir/htg940_board_top_20261020_1118.ltx)
  --device PATTERN        Vivado hardware device pattern
  --port COM_PORT         UART port (default: COM8)
  --verify-only           Verify and list the bundle without touching hardware
  -h, --help              Show this help
EOF
}

[[ $# -ge 1 ]] || { usage; exit 2; }
case "$1" in
    -h|--help)
        usage
        exit 0
        ;;
esac

bundle="$1"
shift
helper_dir="/mnt/c/Users/marcovisaya/OneDrive - Microsoft/Desktop/htg940/marco"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_bitstream=""
probes=""
device=""
port="COM8"
verify_only=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --helper-dir)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            helper_dir="$2"
            shift 2
            ;;
        --output-bitstream)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            output_bitstream="$2"
            shift 2
            ;;
        --probes)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            probes="$2"
            shift 2
            ;;
        --device)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            device="$2"
            shift 2
            ;;
        --port)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            port="$2"
            shift 2
            ;;
        --verify-only)
            verify_only=true
            shift
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

[[ -f "$bundle" ]] || {
    echo "ERROR: Bundle does not exist: $bundle" >&2
    exit 2
}
[[ "$port" =~ ^COM[0-9]+$ ]] || {
    echo "ERROR: Invalid COM port: $port" >&2
    exit 2
}

for command in grep mktemp sha384sum unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "ERROR: Required command is not installed: $command" >&2
        exit 2
    }
done

bundle="$(realpath -- "$bundle")"
if [[ "$verify_only" == true ]]; then
    extract_dir="$(mktemp -d)"
else
    [[ -d "$helper_dir" ]] || {
        echo "ERROR: Helper directory does not exist: $helper_dir" >&2
        exit 2
    }
    extract_dir="$(mktemp -d "$helper_dir/.fpga-bundle.XXXXXX")"
fi
monitor_pid=""
cleanup() {
    if [[ -n "$monitor_pid" ]] && kill -0 "$monitor_pid" 2>/dev/null; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
    fi
    rm -rf -- "$extract_dir"
}
trap cleanup EXIT

artifacts=(
    caliptra_rom.bin
    mcu_rom.bin
    caliptra_fw.bin
    soc_manifest.bin
    mcu_runtime.bin
)

unzip -q "$bundle" "${artifacts[@]}" SHA384SUMS -d "$extract_dir"

declare -A unchecked=()
for artifact in "${artifacts[@]}"; do
    [[ -f "$extract_dir/$artifact" ]] || {
        echo "ERROR: Bundle is missing $artifact" >&2
        exit 1
    }
    unchecked["$artifact"]=1
done

while read -r digest filename extra; do
    if [[ ! "$digest" =~ ^[0-9a-fA-F]{96}$ || -n "${extra:-}" || -z "${unchecked[$filename]+present}" ]]; then
        echo "ERROR: Invalid SHA384SUMS entry for ${filename:-<missing filename>}" >&2
        exit 1
    fi
    unset 'unchecked[$filename]'
done <"$extract_dir/SHA384SUMS"

if (( ${#unchecked[@]} != 0 )); then
    echo "ERROR: SHA384SUMS does not cover every required artifact." >&2
    exit 1
fi

(
    cd "$extract_dir"
    sha384sum -c SHA384SUMS
)
echo "Bundle verification passed: $bundle"

if [[ "$verify_only" == true ]]; then
    unzip -l "$bundle"
    exit 0
fi

for helper in update-htg940-roms.ps1 program-htg940.sh monitor-htg940.sh run-usb-recovery.sh; do
    [[ -f "$helper_dir/$helper" ]] || {
        echo "ERROR: Required helper does not exist: $helper_dir/$helper" >&2
        exit 2
    }
done

if [[ -z "$output_bitstream" ]]; then
    output_bitstream="${bundle%.zip}.bit"
fi
output_bitstream="$(realpath -m -- "$output_bitstream")"
mkdir -p -- "$(dirname -- "$output_bitstream")"

if [[ -z "$probes" ]]; then
    probes="$helper_dir/htg940_board_top_20261020_1118.ltx"
fi
if [[ -n "$probes" && ! -f "$probes" ]]; then
    echo "ERROR: Probes file does not exist: $probes" >&2
    exit 2
fi

uart_log="${output_bitstream%.bit}.uart.log"
recovery_log="${output_bitstream%.bit}.recovery.log"

echo "Creating bitstream: $output_bitstream"
bash "$script_dir/update-htg940-roms.sh" \
    "$extract_dir/caliptra_rom.bin" \
    "$extract_dir/mcu_rom.bin" \
    "$output_bitstream" \
    "$helper_dir"

program_args=("$output_bitstream")
if [[ -n "$probes" ]]; then
    program_args+=("$probes")
fi
if [[ -n "$device" ]]; then
    if [[ -z "$probes" ]]; then
        program_args+=("")
    fi
    program_args+=("$device")
fi

echo "Programming FPGA"
bash "$helper_dir/program-htg940.sh" "${program_args[@]}"

if [[ -f "$helper_dir/.serial-restart/watcher.ready" && -f "$helper_dir/restart-htg940-serial.sh" ]]; then
    bash "$helper_dir/restart-htg940-serial.sh"
fi

: >"$uart_log"
: >"$recovery_log"
echo "Starting UART capture: $uart_log"
bash "$helper_dir/monitor-htg940.sh" "$port" 180 2>&1 | tee "$uart_log" &
monitor_pid=$!

wait_for_log() {
    local pattern="$1"
    local timeout_seconds="$2"
    local start_line="${3:-1}"
    local deadline=$((SECONDS + timeout_seconds))

    while (( SECONDS < deadline )); do
        if grep -q -- "$pattern" < <(tail -n "+$start_line" "$uart_log"); then
            return 0
        fi
        if ! kill -0 "$monitor_pid" 2>/dev/null; then
            wait "$monitor_pid" || true
            echo "ERROR: UART monitor exited before observing: $pattern" >&2
            return 1
        fi
        sleep 1
    done

    echo "ERROR: Timed out waiting for UART output: $pattern" >&2
    return 1
}

wait_for_log "\[HOST\] Releasing subsystem reset" 90
live_boot_line="$(grep -n "\[HOST\] Releasing subsystem reset" "$uart_log" | tail -1 | cut -d: -f1)"
wait_for_log "Requesting recovery image 0" 150 "$live_boot_line"

recovery_succeeded=false
for attempt in 1 2 3; do
    attempt_log="$extract_dir/recovery-attempt-$attempt.log"
    echo "USB recovery attempt $attempt"
    set +e
    timeout 90s bash "$helper_dir/run-usb-recovery.sh" \
        "$extract_dir/caliptra_fw.bin" \
        "$extract_dir/soc_manifest.bin" \
        "$extract_dir/mcu_runtime.bin" \
        2>&1 | tee "$attempt_log"
    status=${PIPESTATUS[0]}
    set -e
    cat "$attempt_log" >>"$recovery_log"

    if [[ $status -eq 0 ]]; then
        recovery_succeeded=true
        break
    fi
    if [[ $attempt -lt 3 ]] && grep -q "OCP PROT_CAP read failed:.*Pipe error" "$attempt_log"; then
        sleep 2
        continue
    fi
    echo "ERROR: USB recovery failed with status $status. See $recovery_log" >&2
    exit 1
done

[[ "$recovery_succeeded" == true ]] || {
    echo "ERROR: USB recovery did not succeed. See $recovery_log" >&2
    exit 1
}

wait_for_log "\[mcu-runtime\] Hello from MCU runtime" 60

if grep -qi "0x000B0016" "$uart_log"; then
    echo "ERROR: MCU firmware authorization failed with 0x000B0016." >&2
    exit 1
fi

expected_digest="$(sha384sum "$extract_dir/mcu_runtime.bin" | cut -d ' ' -f 1)"
if ! grep -qi "Verifying MCU digest: $expected_digest" "$uart_log"; then
    echo "WARNING: Runtime started, but the expected MCU digest line was not captured." >&2
fi

echo "FPGA bundle test passed."
echo "Bitstream: $output_bitstream"
echo "UART log: $uart_log"
echo "Recovery log: $recovery_log"