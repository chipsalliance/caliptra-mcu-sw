#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/bundle-common.sh"

usage() {
    cat <<EOF
Usage: $0 [bundle.zip] [options]
  --build                  Build images and create the bundle first
  --verify-only            Verify only (default; no hardware access)
  --prepare-only           Verify and repack, without programming
  --program                Repack, program over volatile JTAG, and run recovery
  --helper-dir PATH        Windows HTG helper directory
  --recovery-dir PATH      Working USB Python directory
  --python PATH            WSL path to a Windows python.exe (default: Windows py -3 interpreter)
  --base-bitstream PATH    Default: helper-dir/htg940_board_top_forced_ulpi.bit
  --memory-map PATH        Default: helper-dir/htg940_board_top_forced_ulpi.mmi
  --probes PATH            Default: helper-dir/htg940_usb_dual_ila_forced_ulpi.ltx
  --output-bitstream PATH  Default: timestamped file in helper-dir
  --device PATTERN         Unique Vivado hardware device pattern (default: *)
  --port COM_PORT          UART port (default: COM8)
  --state-timeout SECONDS  USB progress timeout (default: 15)
  --startup-timeout SECONDS Console startup/log-drain timeout (default: 90)
  --diagnostic-seconds SECONDS Continue UART capture after a recovery failure (default: 2)
  -h, --help               Show this help
EOF
}
bundle="$default_bundle"
helper_dir="$default_helper_dir"
recovery_dir="$default_recovery_dir"
base_bit=""; memory_map=""; probes=""; output=""; device="*"; port="COM8"
python_override=""
mode=verify
build=false
state_timeout=15
startup_timeout=90
diagnostic_seconds=2
bundle_supplied=false
while (( $# )); do
    case "$1" in
        --helper-dir|--recovery-dir|--python|--base-bitstream|--memory-map|--probes|--output-bitstream|--device|--port|--state-timeout|--startup-timeout|--diagnostic-seconds)
            (( $# >= 2 )) || fail "$1 requires a value"
            case "$1" in
                --helper-dir) helper_dir="$2" ;; --recovery-dir) recovery_dir="$2" ;;
                --python) python_override="$2" ;;
                --base-bitstream) base_bit="$2" ;; --memory-map) memory_map="$2" ;;
                --probes) probes="$2" ;; --output-bitstream) output="$2" ;;
                --device) device="$2" ;; --port) port="$2" ;; --state-timeout) state_timeout="$2" ;;
                --startup-timeout) startup_timeout="$2" ;;
                --diagnostic-seconds) diagnostic_seconds="$2" ;;
            esac
            shift 2 ;;
        --build) build=true; shift ;;
        --verify-only) mode=verify; shift ;;
        --prepare-only) mode=prepare; shift ;;
        --program) mode=program; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) fail "Unknown argument: $1" ;;
        *)
            [[ "$bundle_supplied" == false ]] || fail "Only one bundle may be supplied"
            bundle="$1"; bundle_supplied=true; shift ;;
    esac
done
[[ "$port" =~ ^COM[0-9]+$ ]] || fail "Invalid UART port: $port"
[[ "$state_timeout" =~ ^[1-9][0-9]*$ ]] || fail "State timeout must be a positive integer"
[[ "$startup_timeout" =~ ^[1-9][0-9]*$ ]] || fail "Startup timeout must be a positive integer"
[[ "$diagnostic_seconds" =~ ^[0-9]+$ ]] || fail "Diagnostic capture duration must be a nonnegative integer"
require_tools unzip sha384sum realpath
bundle="$(realpath -m -- "$bundle")"
if [[ "$build" == true ]]; then
    bash "$bundle_script_dir/build-htg940-fpga-artifacts.sh"
    bash "$bundle_script_dir/create-htg940-fpga-bundle.sh" --output "$bundle"
fi
if [[ "$mode" == verify ]]; then
    extract_dir="$(mktemp -d)"
else
    helper_dir="$(realpath -- "$helper_dir")"
    extract_dir="$(mktemp -d "$helper_dir/.fpga-bundle.XXXXXX")"
fi
trap 'cleanup_bundle_stage "$extract_dir"' EXIT
verify_bundle "$bundle" "$extract_dir"
echo "Bundle verification passed: $bundle"
if [[ "$mode" == verify ]]; then exit 0; fi

output="${output:-$helper_dir/htg940-fpga-test-$(date -u +%Y%m%d-%H%M%S).bit}"
output="$(realpath -m -- "$output")"
if [[ "$mode" == program ]]; then
    require_tools wslpath powershell.exe
    require_file "$helper_dir/program-htg940.sh"
    probes="${probes:-$helper_dir/htg940_usb_dual_ila_forced_ulpi.ltx}"
    require_file "$probes"
    recovery_dir="$(realpath -- "$recovery_dir")"
    if [[ -n "$python_override" ]]; then
        python="$python_override"
    else
        require_tools py.exe
        windows_python="$(py.exe -3 -c 'import sys; print(sys.executable)' | tr -d '\r')"
        python="$(wslpath -u "$windows_python")"
    fi
    echo "Using Windows Python: $python"
    for input in "$python" "$recovery_dir/usb_recovery.py" "$recovery_dir/htg940_console_updated.py" "$recovery_dir/entropy_host.py"; do
        require_file "$input"
    done
    "$python" "$(wslpath -w "$bundle_script_dir/run-htg940-recovery.py")" \
        --recovery-dir "$(wslpath -w "$recovery_dir")" --port "$port" --preflight
fi
update_args=("$extract_dir/caliptra_rom.bin" "$extract_dir/mcu_rom.bin" "$output" "$helper_dir")
if [[ -n "$base_bit" ]]; then update_args+=(--base-bitstream "$base_bit"); fi
if [[ -n "$memory_map" ]]; then update_args+=(--memory-map "$memory_map"); fi
bash "$bundle_script_dir/update-htg940-roms.sh" "${update_args[@]}"
if [[ "$mode" == prepare ]]; then exit 0; fi
echo "Programming FPGA over volatile JTAG: $output"
bash "$helper_dir/program-htg940.sh" "$output" "$probes" "$device"
log_prefix="${output%.bit}"
"$python" "$(wslpath -w "$bundle_script_dir/run-htg940-recovery.py")" \
    --recovery-dir "$(wslpath -w "$recovery_dir")" --port "$port" \
    --caliptra-fmc-rt "$(wslpath -w "$extract_dir/caliptra_fw.bin")" \
    --soc-manifest "$(wslpath -w "$extract_dir/soc_manifest.bin")" \
    --mcu-runtime "$(wslpath -w "$extract_dir/mcu_runtime.bin")" \
    --log-prefix "$(wslpath -w "$log_prefix")" --state-timeout "$state_timeout" \
    --startup-timeout "$startup_timeout" --diagnostic-seconds "$diagnostic_seconds"
