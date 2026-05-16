#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Build and publish FPGA SPDM release artifacts to GitHub.
#
# Usage:
#   ./scripts/build-fpga-spdm-release.sh <release-tag> [--draft] [--prerelease]
#
# Prerequisites:
#   - gh (GitHub CLI) installed and authenticated
#   - Rust toolchain with riscv32imc and aarch64 targets
#   - gcc-aarch64-linux-gnu, squashfs-tools, cmake installed
#     (script will attempt to install them via apt if missing)
#
# The script produces and uploads the following release assets:
#   caliptra-bitstream.pdi            - FPGA bitstream
#   caliptra-binaries.tar.gz          - ROM + runtime firmware (contains all-fw.zip)
#   xtask                             - aarch64 xtask binary for FPGA bootstrap
#   caliptra-test-binaries.sqsh       - squashfs image of test binaries
#   spdm-emu-binaries.tar.gz          - aarch64 spdm-emu binaries + certs

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPENSSL_VERSION="3.5.2"
OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

SPDM_EMU_REPO="https://github.com/parvathib/spdm-emu.git"
SPDM_EMU_BRANCH="pbhogaraju/spdm_emu_main_custom"

REPO="mlvisaya/caliptra-mcu-sw"

OPENSSL_NATIVE_DIR="/tmp/openssl/native"
OPENSSL_ARM_DIR="/tmp/openssl/arm"
STAGING_DIR="/tmp/caliptra-release-staging"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <release-tag> [--draft] [--prerelease]" >&2
    exit 1
fi

RELEASE_TAG="$1"
shift

GH_FLAGS=("--repo" "${REPO}" "--title" "${RELEASE_TAG}" "--notes" "Automated FPGA SPDM release ${RELEASE_TAG}")
for arg in "$@"; do
    case "$arg" in
        --draft)      GH_FLAGS+=("--draft") ;;
        --prerelease) GH_FLAGS+=("--prerelease") ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "==> $*"; }

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "Required command '$1' not found. Install it and retry." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
require_cmd gh
require_cmd cargo
require_cmd rustup
require_cmd git
require_cmd cmake
require_cmd mksquashfs

if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
    log "aarch64-linux-gnu-gcc not found; attempting install via apt..."
    sudo apt-get update -qy
    sudo apt-get install -y gcc-aarch64-linux-gnu squashfs-tools cmake
fi

log "Installing Rust targets..."
rustup target add riscv32imc-unknown-none-elf
rustup target add aarch64-unknown-linux-gnu

# ---------------------------------------------------------------------------
# Working directories
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

# ---------------------------------------------------------------------------
# Build OpenSSL (native x86_64 + aarch64)
# ---------------------------------------------------------------------------
build_openssl() {
    log "Building OpenSSL ${OPENSSL_VERSION}..."

    local BUILD_DIR
    BUILD_DIR="$(mktemp -d)"
    pushd "${BUILD_DIR}"

    curl -fL "${OPENSSL_URL}" -o openssl.tar.gz
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c || {
        echo "OpenSSL tarball hash mismatch." >&2
        exit 1
    }

    tar -xf openssl.tar.gz
    cp -r "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}-arm"

    log "Building OpenSSL native (x86_64)..."
    pushd "openssl-${OPENSSL_VERSION}"
    ./config no-shared no-apps no-quic
    make -j"$(nproc)" build_sw
    popd

    log "Building OpenSSL ARM (aarch64)..."
    pushd "openssl-${OPENSSL_VERSION}-arm"
    export CROSS_COMPILE="aarch64-linux-gnu-"
    ./config linux-aarch64 no-shared no-apps no-quic --cross-compile-prefix="${CROSS_COMPILE}"
    make -j"$(nproc)" build_sw
    popd

    mkdir -p "${OPENSSL_NATIVE_DIR}/lib"
    mv "openssl-${OPENSSL_VERSION}/include"    "${OPENSSL_NATIVE_DIR}/include"
    mv "openssl-${OPENSSL_VERSION}/libcrypto.a" "${OPENSSL_NATIVE_DIR}/lib/"
    mv "openssl-${OPENSSL_VERSION}/libssl.a"    "${OPENSSL_NATIVE_DIR}/lib/"

    mkdir -p "${OPENSSL_ARM_DIR}/lib"
    mv "openssl-${OPENSSL_VERSION}-arm/include"    "${OPENSSL_ARM_DIR}/include"
    mv "openssl-${OPENSSL_VERSION}-arm/libcrypto.a" "${OPENSSL_ARM_DIR}/lib/"
    mv "openssl-${OPENSSL_VERSION}-arm/libssl.a"    "${OPENSSL_ARM_DIR}/lib/"

    popd
    rm -rf "${BUILD_DIR}"
}

if [[ ! -f "${OPENSSL_NATIVE_DIR}/lib/libcrypto.a" || ! -f "${OPENSSL_ARM_DIR}/lib/libcrypto.a" ]]; then
    build_openssl
else
    log "OpenSSL already built, skipping."
fi

# ---------------------------------------------------------------------------
# Download FPGA bitstream
# ---------------------------------------------------------------------------
log "Downloading FPGA bitstream..."
cargo xtask-fpga fpga download-bitstream
mv caliptra-bitstream.pdi "${STAGING_DIR}/caliptra-bitstream.pdi"

# ---------------------------------------------------------------------------
# Build firmware + test binaries
# ---------------------------------------------------------------------------
log "Building FPGA firmware and test binaries..."

export OPENSSL_NO_VENDOR=true
export OPENSSL_STATIC=true
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_NATIVE_DIR}"
export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_ARM_DIR}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

log "Cross-compiling FPGA ROM + runtime..."
cargo xtask-fpga fpga build \
    --configuration subsystem \
    --rom-features "core_test" \
    --mcu_cfg "mcu,0x0,0xB00C0000,2,2,2,test-fpga-flash-ctrl" \
    --separate-runtimes

tar -czf "${STAGING_DIR}/caliptra-binaries.tar.gz" all-fw.zip

log "Cross-compiling test binaries..."
cargo xtask-fpga fpga build-test --configuration subsystem

log "Cross-compiling xtask for FPGA (aarch64)..."
cargo build --package xtask --features=fpga_realtime --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/debug/xtask "${STAGING_DIR}/xtask"

log "Packaging test binaries squashfs..."
local_test_bin_dir="$(mktemp -d)"
tar xf caliptra-test-binaries.tar.zst -C "${local_test_bin_dir}"
mksquashfs "${local_test_bin_dir}" "${STAGING_DIR}/caliptra-test-binaries.sqsh" -comp zstd -noappend
rm -rf "${local_test_bin_dir}"

# ---------------------------------------------------------------------------
# Build spdm-emu for aarch64
# ---------------------------------------------------------------------------
log "Building spdm-emu for aarch64..."

SPDM_EMU_DIR="/tmp/spdm-emu"
rm -rf "${SPDM_EMU_DIR}"
git clone --recursive --branch "${SPDM_EMU_BRANCH}" "${SPDM_EMU_REPO}" "${SPDM_EMU_DIR}"

pushd "${SPDM_EMU_DIR}"
mkdir build
pushd build
cmake -DARCH=aarch64 -DTOOLCHAIN=AARCH64_GCC -DTARGET=Debug -DCRYPTO=openssl ..
make copy_sample_key
make -j"$(nproc)"
popd
popd

SPDM_EMU_STAGING="${STAGING_DIR}/spdm-emu-binaries"
mkdir -p "${SPDM_EMU_STAGING}"
cp -r "${SPDM_EMU_DIR}/build/bin/." "${SPDM_EMU_STAGING}/"

# Replace default CA cert with the one that signed the IDevID CSR
cp ocp-eat-verifier/ocptoken/test-data/ta-store/roots/slot0_ecc_test_root_ca.der \
    "${SPDM_EMU_STAGING}/ecp384/ca.cert.der"

tar -czf "${STAGING_DIR}/spdm-emu-binaries.tar.gz" -C "${STAGING_DIR}" spdm-emu-binaries
rm -rf "${SPDM_EMU_STAGING}"

# ---------------------------------------------------------------------------
# List staged artifacts
# ---------------------------------------------------------------------------
log "Staged artifacts:"
ls -lh "${STAGING_DIR}"

# ---------------------------------------------------------------------------
# Create GitHub release and upload assets
# ---------------------------------------------------------------------------
log "Creating GitHub release '${RELEASE_TAG}' at ${REPO}..."

gh release create "${RELEASE_TAG}" \
    "${GH_FLAGS[@]}" \
    "${STAGING_DIR}/caliptra-bitstream.pdi" \
    "${STAGING_DIR}/caliptra-binaries.tar.gz" \
    "${STAGING_DIR}/xtask" \
    "${STAGING_DIR}/caliptra-test-binaries.sqsh" \
    "${STAGING_DIR}/spdm-emu-binaries.tar.gz"

log "Release '${RELEASE_TAG}' published successfully."
log "View at: https://github.com/${REPO}/releases/tag/${RELEASE_TAG}"
