#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Build and publish FPGA (non-SPDM) release artifacts to GitHub.
#
# Artifacts are split across release tags derived from <release-tag>:
#
#   <release-tag>b   caliptra-bitstream.pdi   (shared with SPDM build)
#   <release-tag>f   caliptra-binaries.tar.gz
#                    caliptra-test-binaries.sqsh
#
# Each tag is skipped (build + upload) if its GitHub release already exists.
#
# Usage:
#   ./scripts/build-fpga-release.sh <release-tag> [--draft] [--prerelease]
#
# Prerequisites:
#   - gh (GitHub CLI) installed and authenticated
#   - Rust toolchain with riscv32imc and aarch64 targets
#   - gcc-aarch64-linux-gnu, squashfs-tools installed
#     (script will attempt to install them via apt if missing)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPENSSL_VERSION="3.5.2"
OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

REPO="mlvisaya/caliptra-mcu-sw"

OPENSSL_NATIVE_DIR="/tmp/openssl/native"
OPENSSL_ARM_DIR="/tmp/openssl/arm"
STAGING_DIR="/tmp/caliptra-fpga-release-staging"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <release-tag> [--draft] [--prerelease]" >&2
    exit 1
fi

RELEASE_TAG="$1"
shift

BITSTREAM_TAG="${RELEASE_TAG}b"
FIRMWARE_TAG="${RELEASE_TAG}f"
GH_EXTRA_FLAGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --draft)      GH_EXTRA_FLAGS+=("--draft");      shift ;;
        --prerelease) GH_EXTRA_FLAGS+=("--prerelease"); shift ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

# Common flags for every gh release create call
gh_release_flags() {
    echo --repo "${REPO}" "${GH_EXTRA_FLAGS[@]}"
}

# Returns 0 if a release tag already exists on GitHub, 1 otherwise.
release_exists() {
    gh release view "$1" --repo "${REPO}" &>/dev/null
}

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
require_cmd mksquashfs

if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
    log "aarch64-linux-gnu-gcc not found; attempting install via apt..."
    sudo apt-get update -qy
    sudo apt-get install -y gcc-aarch64-linux-gnu squashfs-tools zstd
fi

if ! command -v zstd &>/dev/null; then
    log "zstd not found; installing..."
    sudo apt-get install -y zstd
fi

log "Installing Rust targets..."
rustup target add riscv32imc-unknown-none-elf
rustup target add aarch64-unknown-linux-gnu

if ! command -v cargo-nextest &>/dev/null; then
    log "cargo-nextest not found; installing compatible version for rustc 1.85..."
    cargo install cargo-nextest --version 0.9.100 --locked
fi

# ---------------------------------------------------------------------------
# Working directories
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

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
# Download FPGA bitstream  (skipped if release already exists)
# ---------------------------------------------------------------------------
if release_exists "${BITSTREAM_TAG}"; then
    log "Bitstream release '${BITSTREAM_TAG}' already exists, skipping."
else
    log "Downloading FPGA bitstream (tag: ${BITSTREAM_TAG})..."
    cargo install --git https://github.com/chipsalliance/caliptra-infra caliptra-bitstream-downloader --root /tmp/bitstream-downloader --rev 3db904cf9cd704fcf890da32fd61dd30bfce8d11
    /tmp/bitstream-downloader/bin/caliptra-bitstream-downloader --bitstream-manifest hw/fpga/bitstream_manifests/subsystem.toml
    mv subsystem.pdi "${STAGING_DIR}/caliptra-bitstream.pdi"

    log "Creating bitstream release '${BITSTREAM_TAG}'..."
    gh release create "${BITSTREAM_TAG}" \
        $(gh_release_flags) \
        --title "${BITSTREAM_TAG}" \
        --notes "FPGA bitstream" \
        "${STAGING_DIR}/caliptra-bitstream.pdi"
fi

# ---------------------------------------------------------------------------
# Build firmware
# ---------------------------------------------------------------------------
build_firmware() {
    log "Building FPGA firmware..."

    export OPENSSL_NO_VENDOR=true
    export OPENSSL_STATIC=true
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_NATIVE_DIR}"
    export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_ARM_DIR}"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

    # Match the runtime features from fpga.yml
    local RUNTIME_FEATURES="test-i3c-simple,test-i3c-constant-writes,test-fpga-flash-ctrl,test-pldm-fw-update-e2e,test-mcu-mbox-usermode,test-mcu-mbox-cmds,test-mctp-vdm-cmds,test-mcu-mbox-fips-self-test,test-mcu-mbox-fips-periodic"

    log "Cross-compiling FPGA ROM + runtime..."
    cargo xtask-fpga all-build --platform fpga \
        --rom-features "core_test" \
        --runtime-features "${RUNTIME_FEATURES}" \
        --mcu_cfg "mcu,0x0,0xB00C0000,2,2,2,test-fpga-flash-ctrl" \
        --separate-runtimes

    cp target/all-fw.zip all-fw.zip
    tar -czf "${STAGING_DIR}/caliptra-binaries.tar.gz" target/all-fw.zip
}

# ---------------------------------------------------------------------------
# Build test binaries
# ---------------------------------------------------------------------------
build_test_binaries() {
    log "Cross-compiling test binaries..."

    export OPENSSL_NO_VENDOR=true
    export OPENSSL_STATIC=true
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_NATIVE_DIR}"
    export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_ARM_DIR}"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

    local FEATURES="fpga_realtime"
    cargo nextest archive \
      --features="${FEATURES}" \
      --release \
      --target=aarch64-unknown-linux-gnu \
      --archive-file=caliptra-test-binaries.tar.zst

    local local_test_bin_dir
    local_test_bin_dir="$(mktemp -d)"
    tar xf caliptra-test-binaries.tar.zst -C "${local_test_bin_dir}"
    mksquashfs "${local_test_bin_dir}" "${STAGING_DIR}/caliptra-test-binaries.sqsh" -comp zstd -noappend
    rm -rf "${local_test_bin_dir}"
}

build_firmware
build_test_binaries

# ---------------------------------------------------------------------------
# List staged artifacts
# ---------------------------------------------------------------------------
log "Staged artifacts:"
ls -lh "${STAGING_DIR}"

# ---------------------------------------------------------------------------
# Create firmware release and upload assets
# ---------------------------------------------------------------------------
if release_exists "${FIRMWARE_TAG}"; then
    log "Firmware release '${FIRMWARE_TAG}' already exists — deleting and re-creating..."
    gh release delete "${FIRMWARE_TAG}" --repo "${REPO}" --yes
    git push --delete "https://github.com/${REPO}.git" "${FIRMWARE_TAG}" 2>/dev/null || true
fi

log "Creating firmware release '${FIRMWARE_TAG}' at ${REPO}..."
gh release create "${FIRMWARE_TAG}" \
    $(gh_release_flags) \
    --title "${FIRMWARE_TAG}" \
    --notes "FPGA test firmware artifacts. Bitstream: ${BITSTREAM_TAG}" \
    "${STAGING_DIR}/caliptra-binaries.tar.gz" \
    "${STAGING_DIR}/caliptra-test-binaries.sqsh"

log "Firmware release '${FIRMWARE_TAG}' published."

log "Done."
