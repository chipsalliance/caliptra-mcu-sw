#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Run FPGA tests remotely on the board via SSH.
#
# Assumes artifacts have already been deployed via build_fpga_artifacts.sh --deploy.
#
# Usage:
#   ./run_fpga_tests.sh                        # run all tests
#   ./run_fpga_tests.sh --bootstrap            # load bitstream before testing
#   ./run_fpga_tests.sh --filter "test_name"   # run specific test(s) by name
#   ./run_fpga_tests.sh --list                 # list available tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

SSH_KEY="${HOME}/.ssh/no_passwd_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# Remote paths (must match build_fpga_artifacts.sh)
REMOTE_DIR="/tmp/caliptra-binaries"
REMOTE_TEST_DIR="/tmp/caliptra-test-binaries"
REMOTE_BITSTREAM_DIR="/tmp/caliptra-bitstream"

BOOTSTRAP=false
LIST_ONLY=false
TEST_FILTER=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --bootstrap         Load bitstream before running tests
  --filter <pattern>  Run only tests matching the given pattern
  --list              List available tests without running them
  -h, --help          Show this help message

Environment:
  FPGA_IP     IP address of the FPGA board (loaded from scripts/.env)
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bootstrap)  BOOTSTRAP=true; shift ;;
        --filter)     TEST_FILTER="$2"; shift 2 ;;
        --list)       LIST_ONLY=true; shift ;;
        -h|--help)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Load FPGA_IP from .env
if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${ENV_FILE}"
fi

if [[ -z "${FPGA_IP:-}" ]]; then
    echo "[!] FPGA_IP not set. Run setup_fpga.py first or set FPGA_IP in ${ENV_FILE}."
    exit 1
fi

REMOTE="root@${FPGA_IP}"
SSH_CMD="ssh -i ${SSH_KEY} ${SSH_OPTS}"

run_remote() {
    ${SSH_CMD} "${REMOTE}" "$@"
}

# Verify artifacts exist on the board
echo "[*] Verifying artifacts on ${FPGA_IP}..."
run_remote "test -x ${REMOTE_DIR}/xtask && test -f ${REMOTE_DIR}/all-fw.zip && test -d ${REMOTE_TEST_DIR}/target" || {
    echo "[!] Artifacts not found on FPGA board. Run: ./build_fpga_artifacts.sh --deploy"
    exit 1
}
echo "[+] Artifacts verified."

# Bootstrap bitstream if requested
if $BOOTSTRAP; then
    if ! run_remote "test -f ${REMOTE_BITSTREAM_DIR}/caliptra-bitstream.pdi" 2>/dev/null; then
        echo "[!] Bitstream not found on board. Deploy with: ./build_fpga_artifacts.sh --with-bitstream --deploy"
        exit 1
    fi
    echo "[*] Loading bitstream..."
    run_remote "${REMOTE_DIR}/xtask fpga bootstrap --bitstream ${REMOTE_BITSTREAM_DIR}/caliptra-bitstream.pdi"
    echo "[+] Bitstream loaded."
fi

# Build the environment variables block
ENV_BLOCK="export RUST_BACKTRACE=1; \
export TEST_BIN=${REMOTE_TEST_DIR}; \
export CPTRA_FIRMWARE_BUNDLE=${REMOTE_DIR}/all-fw.zip"

if $LIST_ONLY; then
    echo "[*] Listing available tests..."
    run_remote "${ENV_BLOCK}; \
        cargo-nextest nextest list \
            --cargo-metadata=\"\${TEST_BIN}/target/nextest/cargo-metadata.json\" \
            --binaries-metadata=\"\${TEST_BIN}/target/nextest/binaries-metadata.json\" \
            --target-dir-remap=\"\${TEST_BIN}/target\" \
            --workspace-remap=. \
            2>/dev/null || ${REMOTE_DIR}/xtask fpga test --list 2>/dev/null || echo 'Test listing not supported'"
    exit 0
fi

echo "[*] Running FPGA tests on ${FPGA_IP}..."

if [[ -n "${TEST_FILTER}" ]]; then
    echo "[*] Test filter: ${TEST_FILTER}"
    run_remote "${ENV_BLOCK}; ${REMOTE_DIR}/xtask fpga test --test-filter 'package(caliptra-mcu-tests-integration) & test(${TEST_FILTER})'"
else
    run_remote "${ENV_BLOCK}; ${REMOTE_DIR}/xtask fpga test"
fi

STATUS=$?

# Try to fetch test results
RESULTS_DIR="${SCRIPT_DIR}/fpga-test-results"
mkdir -p "${RESULTS_DIR}"
scp -i "${SSH_KEY}" ${SSH_OPTS} "${REMOTE}:/tmp/junit.xml" "${RESULTS_DIR}/" 2>/dev/null && \
    echo "[+] Test results saved to ${RESULTS_DIR}/junit.xml" || true

if [[ ${STATUS} -eq 0 ]]; then
    echo "[+] All tests passed."
else
    echo "[!] Some tests failed (exit code: ${STATUS})."
fi

exit ${STATUS}
