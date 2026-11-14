#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/bundle-common.sh"

usage() { echo "Usage: $0 [--build-dir PATH] [--output PATH]"; }
build_dir="$default_build_dir"
output="$default_bundle"
while (( $# )); do
    case "$1" in
        --build-dir|--output)
            (( $# >= 2 )) || fail "$1 requires a path"
            if [[ "$1" == --build-dir ]]; then build_dir="$2"; else output="$2"; fi
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unsupported argument: $1; use the artifact directory produced by the build helper" ;;
    esac
done
require_tools git zip unzip sha384sum realpath
build_dir="$(realpath -- "$build_dir")"
output="$(realpath -m -- "$output")"
[[ "$output" != "$build_dir/recovery-images.zip" ]] || fail "Output must not overwrite recovery-images.zip"
for name in "${bundle_files[@]}"; do
    [[ "$name" == BUNDLE_INFO.txt ]] || require_file "$build_dir/$name"
    [[ "$output" != "$build_dir/$name" ]] || fail "Output aliases an input: $name"
done
verify_roms "$build_dir"
core_revision="$(git -C "$bundle_mcu_repo/core/caliptra-sw" rev-parse HEAD)"
ss_revision="$(git -C "$bundle_mcu_repo/hw/latest/caliptra-ss" rev-parse HEAD)"
for provenance in hardware-provenance.txt mcu-rom-provenance.txt; do
    grep -qx 'CALIPTRA_HW_REV=latest' "$build_dir/$provenance" || fail "$provenance is not latest"
    grep -Fxq "MCU subsystem=hw/latest/caliptra-ss $ss_revision" "$build_dir/$provenance" ||
        fail "$provenance does not match the linked subsystem"
    grep -Fxq "Caliptra FMC/runtime source=$core_revision" "$build_dir/$provenance" ||
        fail "$provenance does not match the linked Core"
done
mkdir -p -- "$(dirname -- "$output")"
stage_dir="$(mktemp -d "$(dirname -- "$output")/.htg940-bundle.XXXXXX")"
trap 'cleanup_bundle_stage "$stage_dir"' EXIT
for name in "${bundle_files[@]}"; do
    [[ "$name" == BUNDLE_INFO.txt ]] || cp -- "$build_dir/$name" "$stage_dir/$name"
done
cat >"$stage_dir/BUNDLE_INFO.txt" <<EOF
format_version=2
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mcu_checkout_commit=$(git -C "$bundle_mcu_repo" rev-parse HEAD)
caliptra_commit=$core_revision
subsystem_commit=$ss_revision
otp_mmap_sha256=$(sha256sum "$bundle_mcu_repo/hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson" | cut -d ' ' -f 1)
mcu_rom_feature=htg940
EOF
(
    cd "$stage_dir"
    sha384sum "${bundle_files[@]}" > SHA384SUMS
    zip -q bundle.zip "${bundle_files[@]}" SHA384SUMS
)
mv -- "$stage_dir/bundle.zip" "$output"
echo "Created HTG bundle: $output"
