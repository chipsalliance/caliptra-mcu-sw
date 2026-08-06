#!/usr/bin/env bash
# Licensed under the Apache-2.0 license

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACTS_DIR="${FPGA_ARTIFACTS_DIR:-${SCRIPT_DIR}/fpga-artifacts}"
REPOSITORY="${FPGA_RELEASE_REPOSITORY:-mlvisaya/caliptra-mcu-sw}"

usage() {
    cat <<EOF
Usage: $(basename "$0") <release-tag>

Upload FPGA test artifacts from:
  ${ARTIFACTS_DIR}

Release repository:
  ${REPOSITORY}

Environment overrides:
  FPGA_ARTIFACTS_DIR       Directory containing the built artifacts
  FPGA_RELEASE_REPOSITORY  GitHub repository receiving the release
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 1
fi

RELEASE_TAG="$1"
ASSET_NAMES=(
    caliptra-bitstream.pdi
    caliptra-test-binaries.sqsh
    caliptra-binaries.tar.gz
    xtask
)
ASSET_PATHS=()

for asset_name in "${ASSET_NAMES[@]}"; do
    asset_path="${ARTIFACTS_DIR}/${asset_name}"
    if [[ ! -f "${asset_path}" ]]; then
        echo "[!] Missing release asset: ${asset_path}" >&2
        exit 1
    fi
    ASSET_PATHS+=("${asset_path}")
done

if ! command -v gh >/dev/null 2>&1; then
    echo "[!] GitHub CLI (gh) is required." >&2
    exit 1
fi

gh auth status >/dev/null

if ! gh release view "${RELEASE_TAG}" --repo "${REPOSITORY}" >/dev/null 2>&1; then
    echo "[*] Creating release ${RELEASE_TAG} in ${REPOSITORY}..."
    gh release create "${RELEASE_TAG}" \
        --repo "${REPOSITORY}" \
        --title "FPGA test artifacts ${RELEASE_TAG}" \
        --notes "FPGA test artifacts built from caliptra-mcu-sw."
fi

echo "[*] Uploading FPGA artifacts to ${REPOSITORY} release ${RELEASE_TAG}..."
gh release upload "${RELEASE_TAG}" \
    --repo "${REPOSITORY}" \
    --clobber \
    "${ASSET_PATHS[@]}"

echo "[+] Release assets uploaded:"
gh release view "${RELEASE_TAG}" \
    --repo "${REPOSITORY}" \
    --json assets \
    --jq '.assets[].name'