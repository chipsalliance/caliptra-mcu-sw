#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Build FPGA test artifacts locally and optionally deploy them to the FPGA board.
#
# This mirrors the build_test_binaries CI job from .github/workflows/fpga.yml
# but is tailored for local development.
#
# Usage:
#   ./build_fpga_artifacts.sh                # build only
#   ./build_fpga_artifacts.sh --deploy       # build and deploy to FPGA
#   ./build_fpga_artifacts.sh --deploy-only  # skip build, deploy existing artifacts
#
# Prerequisites:
#   - gcc-aarch64-linux-gnu, squashfs-tools
#   - rustup targets: riscv32imc-unknown-none-elf, aarch64-unknown-linux-gnu
#   - OpenSSL built for native and ARM (see --build-openssl)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${SCRIPT_DIR}/fpga-artifacts"
ENV_FILE="${SCRIPT_DIR}/.env"

# Default OpenSSL dirs (override with env vars if already built elsewhere)
OPENSSL_CACHE_DIR="${OPENSSL_CACHE_DIR:-/tmp/openssl}"
NATIVE_OPENSSL_DIR="${OPENSSL_CACHE_DIR}/native"
ARM_OPENSSL_DIR="${OPENSSL_CACHE_DIR}/arm"

SSH_KEY="${HOME}/.ssh/no_passwd_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

DEPLOY=false
DEPLOY_ONLY=false
BUILD_OPENSSL=false
CONFIGURATION="subsystem"
WITH_BITSTREAM=false
REBUILD_TEST=false

# Remote paths on the FPGA board
REMOTE_DIR="/tmp/caliptra-binaries"
REMOTE_TEST_DIR="/tmp/caliptra-test-binaries"
REMOTE_BITSTREAM_DIR="/tmp/caliptra-bitstream"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --deploy          Build artifacts and deploy to FPGA board
  --deploy-only     Skip build, deploy existing artifacts to FPGA board
  --build-openssl   Build OpenSSL for native and ARM cross-compilation
  --configuration   FPGA configuration mode (default: subsystem)
  --with-bitstream  Download FPGA bitstream (skipped by default)
  --rebuild-test    Force rebuild test binaries even if squashfs exists
  -h, --help        Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deploy)       DEPLOY=true; shift ;;
        --deploy-only)  DEPLOY_ONLY=true; DEPLOY=true; shift ;;
        --build-openssl) BUILD_OPENSSL=true; shift ;;
        --configuration) CONFIGURATION="$2"; shift 2 ;;
        --with-bitstream) WITH_BITSTREAM=true; shift ;;
        --rebuild-test) REBUILD_TEST=true; shift ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

load_env() {
    if [[ -f "${ENV_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${ENV_FILE}"
    fi
}

check_prerequisites() {
    echo "[*] Checking prerequisites..."
    local missing=()

    if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
        missing+=("gcc-aarch64-linux-gnu")
    fi
    if ! command -v mksquashfs &>/dev/null; then
        missing+=("squashfs-tools")
    fi
    if ! rustup target list --installed | grep -q riscv32imc-unknown-none-elf; then
        missing+=("rustup target riscv32imc-unknown-none-elf")
    fi
    if ! rustup target list --installed | grep -q aarch64-unknown-linux-gnu; then
        missing+=("rustup target aarch64-unknown-linux-gnu")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "[!] Missing prerequisites:"
        for m in "${missing[@]}"; do
            echo "    - $m"
        done
        echo ""
        echo "Install with:"
        echo "  sudo apt-get install -y gcc-aarch64-linux-gnu squashfs-tools"
        echo "  rustup target add riscv32imc-unknown-none-elf aarch64-unknown-linux-gnu"
        exit 1
    fi
    echo "[+] All prerequisites found."
}

build_openssl() {
    if [[ -d "${NATIVE_OPENSSL_DIR}/lib" && -d "${ARM_OPENSSL_DIR}/lib" ]] && ! $BUILD_OPENSSL; then
        echo "[*] OpenSSL already built at ${OPENSSL_CACHE_DIR}, skipping. Use --build-openssl to rebuild."
        return
    fi

    echo "[*] Building OpenSSL for native and ARM..."
    local tmpdir
    tmpdir=$(mktemp -d)

    curl -L "https://github.com/openssl/openssl/releases/download/openssl-3.5.2/openssl-3.5.2.tar.gz" \
        -o "${tmpdir}/openssl.tar.gz"

    local expected_hash="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"
    if ! (echo "${expected_hash} ${tmpdir}/openssl.tar.gz" | sha256sum -c); then
        echo "[!] OpenSSL tarball hash mismatch."
        exit 1
    fi

    tar -xf "${tmpdir}/openssl.tar.gz" -C "${tmpdir}"
    cp -r "${tmpdir}/openssl-3.5.2" "${tmpdir}/openssl-3.5.2-arm"

    echo "[*] Building native OpenSSL..."
    pushd "${tmpdir}/openssl-3.5.2" > /dev/null
    ./config no-shared no-apps no-quic
    make -j"$(nproc)" build_sw
    popd > /dev/null

    echo "[*] Building ARM OpenSSL..."
    pushd "${tmpdir}/openssl-3.5.2-arm" > /dev/null
    CROSS_COMPILE="aarch64-linux-gnu-" \
        ./config linux-aarch64 no-shared no-apps no-quic \
        --cross-compile-prefix="aarch64-linux-gnu-"
    make -j"$(nproc)" build_sw
    popd > /dev/null

    mkdir -p "${NATIVE_OPENSSL_DIR}/lib" "${ARM_OPENSSL_DIR}/lib"
    mv "${tmpdir}/openssl-3.5.2/include" "${NATIVE_OPENSSL_DIR}/include"
    mv "${tmpdir}/openssl-3.5.2/libcrypto.a" "${NATIVE_OPENSSL_DIR}/lib/"
    mv "${tmpdir}/openssl-3.5.2/libssl.a" "${NATIVE_OPENSSL_DIR}/lib/"
    mv "${tmpdir}/openssl-3.5.2-arm/include" "${ARM_OPENSSL_DIR}/include"
    mv "${tmpdir}/openssl-3.5.2-arm/libcrypto.a" "${ARM_OPENSSL_DIR}/lib/"
    mv "${tmpdir}/openssl-3.5.2-arm/libssl.a" "${ARM_OPENSSL_DIR}/lib/"

    rm -rf "${tmpdir}"
    echo "[+] OpenSSL built at ${OPENSSL_CACHE_DIR}"
}

set_openssl_env() {
    export OPENSSL_NO_VENDOR=true
    export OPENSSL_STATIC=true
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${NATIVE_OPENSSL_DIR}"
    export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${ARM_OPENSSL_DIR}"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
}

download_bitstream() {
    if ! $WITH_BITSTREAM; then
        echo "[*] Skipping bitstream download (use --with-bitstream to include)."
        return
    fi

    echo "[*] Downloading FPGA bitstream..."
    cd "${REPO_ROOT}"
    cargo xtask-fpga fpga download-bitstream
    mv caliptra-bitstream.pdi "${ARTIFACTS_DIR}/caliptra-bitstream.pdi"
    echo "[+] Bitstream saved."
}

build_firmware() {
    echo "[*] Building FPGA firmware (configuration: ${CONFIGURATION})..."
    cd "${REPO_ROOT}"

    cargo xtask-fpga fpga build \
        --configuration "${CONFIGURATION}" \
        --rom-features "core_test,hw-2-1" \
        --mcu_cfg mcu,0x0,0xB00C0000,2,2,2,test-fpga-flash-ctrl \
        --separate-runtimes

    echo "[*] Building FPGA release-profile runtime..."
    cargo xtask runtime-build --platform fpga --profile release

    # Package the firmware bundle
    cp all-fw.zip "${ARTIFACTS_DIR}/all-fw.zip"
    echo "[+] Firmware built."
}

build_test_binaries() {
    # Skip if squashfs already exists and --rebuild-test not specified
    if [[ -f "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" ]] && ! $REBUILD_TEST; then
        echo "[*] Test binaries squashfs already exists, skipping. Use --rebuild-test to force rebuild."
        return
    fi

    echo "[*] Building FPGA test binaries..."
    cd "${REPO_ROOT}"

    cargo xtask-fpga fpga build-test --configuration "${CONFIGURATION}" --no-container

    # Skip ARM xtask build if binary already exists
    if [[ -f "${ARTIFACTS_DIR}/xtask" ]]; then
        echo "[*] ARM xtask binary already exists, skipping. Delete ${ARTIFACTS_DIR}/xtask to rebuild."
    else
        echo "[*] Building xtask for ARM..."
        cargo build --package caliptra-mcu-xtask --features=fpga_realtime --target aarch64-unknown-linux-gnu
        cp target/aarch64-unknown-linux-gnu/debug/caliptra-mcu-xtask "${ARTIFACTS_DIR}/xtask"
    fi

    # Extract the nextest archive into a staging dir and create a squashfs image
    local staging_dir
    staging_dir=$(mktemp -d)
    tar xf caliptra-test-binaries.tar.zst -C "${staging_dir}"
    echo "[*] Creating squashfs image from test binaries..."
    mksquashfs "${staging_dir}" "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" -comp gzip -noappend
    rm -rf "${staging_dir}"

    # Also keep the raw archive for direct extraction if preferred
    cp caliptra-test-binaries.tar.zst "${ARTIFACTS_DIR}/caliptra-test-binaries.tar.zst"

    echo "[+] Test binaries built."
}

deploy_to_fpga() {
    load_env

    if [[ -z "${FPGA_IP:-}" ]]; then
        echo "[!] FPGA_IP not set. Run setup_fpga.py first or set FPGA_IP in ${ENV_FILE}."
        exit 1
    fi

    local remote="root@${FPGA_IP}"
    local ssh_cmd="ssh -i ${SSH_KEY} ${SSH_OPTS}"
    local scp_cmd="scp -i ${SSH_KEY} ${SSH_OPTS}"

    echo "[*] Deploying artifacts to ${FPGA_IP}..."

    # Create remote directories
    ${ssh_cmd} "${remote}" "mkdir -p ${REMOTE_DIR} ${REMOTE_TEST_DIR} ${REMOTE_BITSTREAM_DIR}"

    # Copy bitstream (if downloaded)
    if [[ -f "${ARTIFACTS_DIR}/caliptra-bitstream.pdi" ]]; then
        echo "[*] Copying bitstream..."
        ${scp_cmd} "${ARTIFACTS_DIR}/caliptra-bitstream.pdi" "${remote}:${REMOTE_BITSTREAM_DIR}/"
    else
        echo "[*] No bitstream found, skipping. Use --with-bitstream to include."
    fi

    # Copy xtask binary
    echo "[*] Copying xtask..."
    ${scp_cmd} "${ARTIFACTS_DIR}/xtask" "${remote}:${REMOTE_DIR}/"
    ${ssh_cmd} "${remote}" "chmod +x ${REMOTE_DIR}/xtask"

    # Copy firmware bundle
    echo "[*] Copying firmware bundle..."
    ${scp_cmd} "${ARTIFACTS_DIR}/all-fw.zip" "${remote}:${REMOTE_DIR}/"

    # Copy test binaries — prefer squashfs (smaller, faster mount), fall back to tar.zst
    if [[ -f "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" ]]; then
        echo "[*] Copying squashfs test binaries image..."
        ${scp_cmd} "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" "${remote}:/tmp/"
        echo "[*] Mounting squashfs test binaries on FPGA..."
        ${ssh_cmd} "${remote}" "sudo umount ${REMOTE_TEST_DIR} 2>/dev/null || true; \
            rm -rf ${REMOTE_TEST_DIR}; \
            mkdir -p ${REMOTE_TEST_DIR}; \
            sudo mount /tmp/caliptra-test-binaries.sqsh ${REMOTE_TEST_DIR} -t squashfs -o loop"
    elif [[ -f "${ARTIFACTS_DIR}/caliptra-test-binaries.tar.zst" ]]; then
        echo "[*] Copying test binaries archive..."
        ${scp_cmd} "${ARTIFACTS_DIR}/caliptra-test-binaries.tar.zst" "${remote}:/tmp/"
        echo "[*] Extracting test binaries on FPGA..."
        ${ssh_cmd} "${remote}" "rm -rf ${REMOTE_TEST_DIR} && mkdir -p ${REMOTE_TEST_DIR} && tar xf /tmp/caliptra-test-binaries.tar.zst -C ${REMOTE_TEST_DIR} && rm /tmp/caliptra-test-binaries.tar.zst"
    else
        echo "[!] No test binaries found in ${ARTIFACTS_DIR}"
        exit 1
    fi

    # Bootstrap bitstream on FPGA
    if [[ -f "${ARTIFACTS_DIR}/caliptra-bitstream.pdi" ]]; then
        echo "[*] Bootstrapping bitstream on FPGA..."
        ${ssh_cmd} "${remote}" "sudo mkdir -p /lib/firmware"
        ${ssh_cmd} "${remote}" "sudo mv ${REMOTE_BITSTREAM_DIR}/caliptra-bitstream.pdi /lib/firmware"
        ${ssh_cmd} "${remote}" "sudo bash -c 'echo \"caliptra-bitstream.pdi\" > /sys/class/fpga_manager/fpga0/firmware'"
    else
        echo "[*] No bitstream to bootstrap, skipping."
    fi

    echo "[+] Deployment complete."
    echo ""
    echo "On the FPGA board, you can now run:"
    echo "  # Load bitstream"
    echo "  ${REMOTE_DIR}/xtask fpga bootstrap --bitstream ${REMOTE_BITSTREAM_DIR}/caliptra-bitstream.pdi"
    echo ""
    echo "# Run tests"
    echo "export TEST_BIN=${REMOTE_TEST_DIR}"
    echo "export CPTRA_FIRMWARE_BUNDLE=${REMOTE_DIR}/all-fw.zip"
    echo "${REMOTE_DIR}/xtask fpga test"
}

main() {
    if $DEPLOY_ONLY; then
        deploy_to_fpga
        exit 0
    fi

    check_prerequisites

    mkdir -p "${ARTIFACTS_DIR}"

    build_openssl
    set_openssl_env
    download_bitstream
    build_firmware
    build_test_binaries

    echo ""
    echo "[+] All artifacts built in: ${ARTIFACTS_DIR}"
    ls -lh "${ARTIFACTS_DIR}"

    if $DEPLOY; then
        echo ""
        deploy_to_fpga
    else
        echo ""
        echo "To deploy to the FPGA, run:"
        echo "  $0 --deploy-only"
    fi
}

main
