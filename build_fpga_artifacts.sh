#!/bin/bash
# Licensed under the Apache-2.0 license
#
# Build FPGA test artifacts locally. The outputs are placed in the repo
# so they can be committed and uploaded by CI without a lengthy rebuild.
#
# Prerequisites:
#   sudo apt-get install gcc-aarch64-linux-gnu squashfs-tools
#   rustup target add riscv32imc-unknown-none-elf aarch64-unknown-linux-gnu
#   cargo install cargo-nextest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---------- OpenSSL (native + arm) ----------
# Build static OpenSSL for both native and aarch64 if not already cached.
OPENSSL_DIR=/tmp/openssl
if [[ ! -f "$OPENSSL_DIR/native/lib/libcrypto.a" || ! -f "$OPENSSL_DIR/arm/lib/libcrypto.a" ]]; then
    echo "==> Building OpenSSL (native + aarch64)..."
    OPENSSL_VER=3.5.2
    OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"

    pushd /tmp
    curl -L "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" -o openssl.tar.gz
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c

    rm -rf openssl-${OPENSSL_VER} openssl-${OPENSSL_VER}-arm
    tar -xf openssl.tar.gz
    cp -r openssl-${OPENSSL_VER} openssl-${OPENSSL_VER}-arm

    # Native
    pushd openssl-${OPENSSL_VER}
    ./config no-shared no-apps no-quic
    make -j"$(nproc)" build_sw
    popd

    # ARM
    pushd openssl-${OPENSSL_VER}-arm
    CROSS_COMPILE="aarch64-linux-gnu-" ./config linux-aarch64 no-shared no-apps no-quic --cross-compile-prefix="aarch64-linux-gnu-"
    make -j"$(nproc)" build_sw
    popd

    mkdir -p "$OPENSSL_DIR/native/lib" "$OPENSSL_DIR/arm/lib"
    mv openssl-${OPENSSL_VER}/include "$OPENSSL_DIR/native/include"
    mv openssl-${OPENSSL_VER}/libcrypto.a "$OPENSSL_DIR/native/lib/"
    mv openssl-${OPENSSL_VER}/libssl.a "$OPENSSL_DIR/native/lib/"
    mv openssl-${OPENSSL_VER}-arm/include "$OPENSSL_DIR/arm/include"
    mv openssl-${OPENSSL_VER}-arm/libcrypto.a "$OPENSSL_DIR/arm/lib/"
    mv openssl-${OPENSSL_VER}-arm/libssl.a "$OPENSSL_DIR/arm/lib/"

    rm -rf openssl-${OPENSSL_VER} openssl-${OPENSSL_VER}-arm openssl.tar.gz
    popd
    echo "==> OpenSSL built."
else
    echo "==> OpenSSL already cached in $OPENSSL_DIR"
fi

# ---------- Environment ----------
export OPENSSL_NO_VENDOR=true
export OPENSSL_STATIC=true
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$OPENSSL_DIR/native"
export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$OPENSSL_DIR/arm"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
export MCU_STAGING_ADDR=0xB00C0000

# ---------- Build firmware ----------
echo "==> Building FPGA firmware binaries..."
cargo xtask-fpga all-build --platform fpga \
    --rom-features "core_test" \
    --mcu_cfg "mcu,0x0,$MCU_STAGING_ADDR,2,2,2,test-fpga-flash-ctrl" \
    --separate-runtimes

mkdir -p /tmp/caliptra-binaries
tar -cvzf /tmp/caliptra-binaries/caliptra-binaries.tar.gz target/all-fw.zip
echo "==> Firmware built."

# ---------- Build test binaries ----------
echo "==> Building test binaries (aarch64 cross-compile, release)..."
cargo nextest archive \
    --features=fpga_realtime \
    --release \
    --target=aarch64-unknown-linux-gnu \
    --archive-file=/tmp/caliptra-test-binaries.tar.zst

rm -rf /tmp/caliptra-test-binaries
mkdir -p /tmp/caliptra-test-binaries
tar xvf /tmp/caliptra-test-binaries.tar.zst -C /tmp/caliptra-test-binaries/
rm -f /tmp/caliptra-test-binaries.sqsh
mksquashfs /tmp/caliptra-test-binaries /tmp/caliptra-test-binaries.sqsh -comp zstd
echo "==> Test binaries built."

# ---------- Download bitstream ----------
echo "==> Downloading bitstream..."
cargo install --git https://github.com/chipsalliance/caliptra-infra \
    caliptra-bitstream-downloader \
    --root /tmp/bitstream-downloader \
    --rev 3db904cf9cd704fcf890da32fd61dd30bfce8d11
/tmp/bitstream-downloader/bin/caliptra-bitstream-downloader \
    --bitstream-manifest hw/fpga/bitstream_manifests/subsystem.toml
mv subsystem.pdi /tmp/caliptra-bitstream.pdi
echo "==> Bitstream downloaded."

# ---------- Upload to fork release ----------
FORK_REPO="mlvisaya/caliptra-mcu-sw"
RELEASE_TAG="debug-unlock-artifacts"

echo "==> Uploading artifacts to ${FORK_REPO} release ${RELEASE_TAG}..."

# Create the release if it doesn't exist, or delete and recreate to update assets
if gh release view "$RELEASE_TAG" --repo "$FORK_REPO" &>/dev/null; then
    echo "  Release exists, deleting old assets..."
    gh release delete "$RELEASE_TAG" --repo "$FORK_REPO" --yes
fi

gh release create "$RELEASE_TAG" --prerelease \
    --repo "$FORK_REPO" \
    --title "Prebuilt FPGA test artifacts" \
    --notes "Temporary prebuilt artifacts for debug unlock PR" \
    /tmp/caliptra-binaries/caliptra-binaries.tar.gz \
    /tmp/caliptra-test-binaries.sqsh \
    /tmp/caliptra-bitstream.pdi

echo "==> Artifacts uploaded."

# ---------- Summary ----------
echo ""
echo "============================================"
echo "Artifacts built and uploaded to:"
echo "  https://github.com/${FORK_REPO}/releases/tag/${RELEASE_TAG}"
echo "============================================"
