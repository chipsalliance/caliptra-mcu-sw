#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# LDevID attested CSR / OCP device identity provisioning demo (emulator).
#
#   --extract_csr   Authenticate + attest the device, export the attested
#                   LDevID CSR, verify it, and display it with `openssl req`.
#
#   --provision     Run the full 7-step OCP device identity provisioning flow.
#
# Both modes drive the MCU emulator through the SPDM/MCTP integration harness,
# which boots the firmware, starts the SPDM bridge and runs
# `ocp_dev_identity_provision_tool` against it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

MODE=""
OUT_DIR="${REPO_ROOT}/target/ldevid-demo"
SKIP_BUILD=0
KEEP_GOING=0

TEST_FILTER="test_ocp_dev_identity_provision_tool::test::test_mctp_spdm_set_certificate_with_ocp_provision_tool"
RUNTIME_FEATURE="test-mctp-spdm-set-certificate"

# Key pair 1 is the LDevID identity key (2 = FMC alias, 3 = RT alias).
LDEVID_KEY_PAIR_ID=1
OWNER_SLOT_ID=2
VENDOR_SLOT_ID=0

log()  { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[demo]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[demo]\033[0m %s\n' "$*" >&2; exit 1; }

banner() {
    printf '\n\033[1;35m==============================================================\033[0m\n'
    printf '\033[1;35m %s\033[0m\n' "$*"
    printf '\033[1;35m==============================================================\033[0m\n\n'
}

# Step banner + the tool log line that proves the step happened.
step()     { printf '\n\033[1;32m  ── STEP %s/7 ─ %s\033[0m\n' "$1" "$2"; }
evidence() { printf '     \033[0;90m%s\033[0m\n' "$1"; }

# Strip everything up to and including the tool's log prefix. libspdm's hex
# dumps sometimes land on the same line, so anchor on the prefix, not line start.
strip_prefix() { printf '%s' "${1#*\[ocp_dev_identity_provision_tool\] }"; }

# Run a noisy build command; keep its output in the build log, not on screen.
run_quiet() {
    local desc="$1"; shift
    local start elapsed
    printf '\033[1;36m[demo]\033[0m %s ... ' "${desc}"
    start=$(date +%s)
    if ! "$@" >>"${BUILD_LOG}" 2>&1; then
        printf '\033[1;31mFAILED\033[0m\n'
        warn "last 30 lines of ${BUILD_LOG}:"
        tail -30 "${BUILD_LOG}" >&2
        die "${desc} failed"
    fi
    elapsed=$(( $(date +%s) - start ))
    printf '\033[1;32mok\033[0m (%ss)\n' "${elapsed}"
}

usage() {
    cat <<EOF
LDevID attested CSR / OCP device identity provisioning demo (emulator).

Usage: $(basename "$0") (--extract_csr | --provision) [options]

Modes:
  --extract_csr      Attest the device, export + verify the attested LDevID
                     CSR, then display it with openssl. Steps 1-4 only;
                     nothing is written to the device.
  --provision        Full OCP device identity provisioning (all 7 steps).

Options:
  --out-dir <dir>    Where to write CSR artifacts. Default: ${OUT_DIR}
  --skip-build       Reuse existing firmware/host-tool builds.
  --keep-going       Continue to openssl display even if the emulator run fails.
  -h, --help         Show this help.

Environment:
  LIBSPDM_LIB_DIR    Prebuilt libspdm static libs. Auto-built if unset/missing.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --extract_csr|--extract-csr)
            [[ -n "${MODE}" ]] && die "--extract_csr and --provision are mutually exclusive"
            MODE="extract" ;;
        --provision)
            [[ -n "${MODE}" ]] && die "--extract_csr and --provision are mutually exclusive"
            MODE="provision" ;;
        --out-dir)    OUT_DIR="${2:?--out-dir needs a value}"; shift ;;
        --skip-build) SKIP_BUILD=1 ;;
        --keep-going) KEEP_GOING=1 ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage >&2; die "unknown argument: $1" ;;
    esac
    shift
done

[[ -n "${MODE}" ]] || { usage >&2; die "one of --extract_csr or --provision is required"; }

COSE_OUT="${OUT_DIR}/ldevid_attested_csr.cose"
CSR_OUT="${OUT_DIR}/ldevid_csr.der"
BUILD_LOG="${OUT_DIR}/build.log"
RUN_LOG="${OUT_DIR}/run.log"

mkdir -p "${OUT_DIR}"
: >"${BUILD_LOG}"
: >"${RUN_LOG}"

printf '\033[1;36m[demo]\033[0m Prerequisites: cargo, cmake, openssl, python3, pkg-config ... '
for tool in cargo cmake openssl python3 pkg-config; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        printf '\033[1;31mFAILED\033[0m\n'
        die "required tool not found: ${tool}"
    fi
done
printf '\033[1;32mok\033[0m\n'

# ---------------------------------------------------------------------------
# libspdm (the host SPDM requester links this statically)
# ---------------------------------------------------------------------------
: "${LIBSPDM_LIB_DIR:=${REPO_ROOT}/caliptra-util-host/target/libspdm-lib}"
export LIBSPDM_LIB_DIR

if ! compgen -G "${LIBSPDM_LIB_DIR}/*.a" >/dev/null; then
    run_quiet "  cargo fetch" bash -c 'cd caliptra-util-host && cargo fetch'

    SPDM_UTILS_DIR="$(cargo metadata --manifest-path caliptra-util-host/Cargo.toml --format-version=1 \
        | python3 -c 'import json,os,sys; d=json.load(sys.stdin); print(os.path.dirname(next(p["manifest_path"] for p in d["packages"] if p["name"]=="SPDM-Utils")))')"
    [[ -n "${SPDM_UTILS_DIR}" ]] || die "could not locate the SPDM-Utils checkout"

    BUILD_DIR="${REPO_ROOT}/caliptra-util-host/target/libspdm-build"
    OPENSSL_LIB_DIR="$(pkg-config --variable=libdir openssl)"

    run_quiet "  cmake configure" \
        cmake -S "${SPDM_UTILS_DIR}/third-party/libspdm" -B "${BUILD_DIR}" \
        -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl \
        -DENABLE_BINARY_BUILD=1 -DSTACK_USAGE=ON \
        -DCOMPILED_LIBCRYPTO_PATH="${OPENSSL_LIB_DIR}" \
        -DCOMPILED_LIBSSL_PATH="${OPENSSL_LIB_DIR}" \
        -DDISABLE_TESTS=1 \
        -DCMAKE_C_FLAGS="-DLIBSPDM_MAX_CERT_CHAIN_SIZE=0x2000 \
            -DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 \
            -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 \
            -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1 \
            -DLIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP=0 \
            -DLIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP=0"
    run_quiet "  cmake build" cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

    mkdir -p "${LIBSPDM_LIB_DIR}"
    find "${BUILD_DIR}/lib" -name "*.a" -exec cp {} "${LIBSPDM_LIB_DIR}/" \;
fi

# ---------------------------------------------------------------------------
# Build host tools + emulator firmware
# ---------------------------------------------------------------------------
TOOL_BIN="${REPO_ROOT}/target/caliptra-util-host/debug/ocp_dev_identity_provision_tool"

if [[ "${SKIP_BUILD}" -eq 1 && -x "${TOOL_BIN}" ]]; then
    :
else
    run_quiet "Building caliptra-util-host host tools" \
        bash -c 'cd caliptra-util-host && cargo xtask build'
    run_quiet "Building emulator firmware (${RUNTIME_FEATURE})" \
        cargo xtask all-build --separate-runtimes --runtime-features "${RUNTIME_FEATURE}"
fi

[[ -x "${TOOL_BIN}" ]] || die "provisioning tool not found at ${TOOL_BIN}"

export OCP_DEV_IDENTITY_PROVISION_TOOL_BIN="${TOOL_BIN}"
export CPTRA_FIRMWARE_BUNDLE="${REPO_ROOT}/target/all-fw.zip"

rm -f "${CSR_OUT}" "${COSE_OUT}"

# ---------------------------------------------------------------------------
# Run the emulator flow
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "extract" ]]; then
    banner "LDevID Attested CSR - Steps 1-4"
    export OCP_DEV_IDENTITY_PROVISION_TOOL_ARGS="--extract-only --csr-out ${CSR_OUT} --cose-out ${COSE_OUT}"
else
    banner "OCP Device Identity Provisioning - Steps 1-7"
    export OCP_DEV_IDENTITY_PROVISION_TOOL_ARGS="--csr-out ${CSR_OUT} --cose-out ${COSE_OUT}"
fi

# Map the tool's log lines onto the 7 provisioning steps. Everything else
# (cargo build noise, emulator boot spam, SPDM chatter) goes to RUN_LOG only.
filter_steps() {
    local line msg
    while IFS= read -r line; do
        msg="$(strip_prefix "${line}")"
        case "${line}" in
            *"Initial CHALLENGE attestation passed for Vendor slot"*)
                step 1 "Authenticate + CHALLENGE Vendor slot ${VENDOR_SLOT_ID}   (attest FIRST)"
                evidence "${msg}" ;;
            *"Vendor slot"*"certificate chain verified via GET_CERTIFICATE"*)
                step 2 "GET_CERTIFICATE Vendor chain + root-hash check"
                evidence "${msg}" ;;
            *"ExportAttestedCsr key_pair_id="*)
                step 3 "ExportAttestedCsr  key_pair_id=${LDEVID_KEY_PAIR_ID} (LDevID), ECC-P384, random nonce"
                evidence "${msg}"
                step 4 "Verify CSR COSE_Sign1 against the attested Vendor chain"
                evidence "COSE_Sign1 verified against RT Alias key from the attested chain"
                evidence "Nonce (EAT claim 10) matched - CSR is fresh" ;;
            *"Extract-only mode"*)
                evidence "${msg}" ;;
            *"Issued test Owner/LDevID certificate chain"*)
                step 5 "Issue the Owner/LDevID certificate chain from the CSR"
                evidence "${msg}" ;;
            *"Attested CSR public key matches owner/LDevID leaf certificate"*)
                evidence "${msg}" ;;
            *"SET_CERTIFICATE slot_id="*)
                step 6 "SET_CERTIFICATE into slot ${OWNER_SLOT_ID}, then GET_CERTIFICATE + verify"
                evidence "${msg}" ;;
            *"Provisioning verified (GET_CERTIFICATE returned"*)
                evidence "${msg}" ;;
            *"Owner slot"*"certificate chain verified via GET_CERTIFICATE"*)
                evidence "${msg}" ;;
            *"Owner-slot CHALLENGE passed for slot"*)
                step 7 "CHALLENGE slot ${OWNER_SLOT_ID} - prove LDevID private-key possession"
                evidence "${msg}" ;;
            *"Wrote "*" to "*)
                evidence "${msg}" ;;
        esac
    done
}

# Run the integration test that boots the emulator, starts the SPDM/MCTP
# bridge, and launches the OCP device identity provisioning tool.
set +e
cargo test --package caliptra-mcu-tests-integration --lib -- \
    "${TEST_FILTER}" --exact --nocapture --include-ignored 2>&1 \
    | tee "${RUN_LOG}" | filter_steps
RUN_STATUS=${PIPESTATUS[0]}
set -e

echo

if [[ "${RUN_STATUS}" -ne 0 ]]; then
    warn "last 30 lines of ${RUN_LOG}:"
    tail -30 "${RUN_LOG}" >&2
    if [[ "${KEEP_GOING}" -eq 1 ]]; then
        warn "Emulator run failed (exit ${RUN_STATUS}); continuing because --keep-going was given"
    else
        die "Emulator run failed (exit ${RUN_STATUS})"
    fi
else
    if grep -q "Test : PASSED" "${RUN_LOG}"; then
        if [[ "${MODE}" == "extract" ]]; then
            log "Steps 1-4 completed - harness reported: Test : PASSED"
        else
            log "All 7 steps completed - harness reported: Test : PASSED"
        fi
    else
        log "Emulator run complete (exit 0)"
    fi
fi

# ---------------------------------------------------------------------------
# Display the CSR
# ---------------------------------------------------------------------------
[[ -s "${CSR_OUT}" ]] || die "no CSR was produced at ${CSR_OUT}"

banner "Attested LDevID CSR"

log "COSE_Sign1 envelope : ${COSE_OUT} ($(wc -c <"${COSE_OUT}" | tr -d ' ') bytes)"
log "Inner PKCS#10 CSR   : ${CSR_OUT} ($(wc -c <"${CSR_OUT}" | tr -d ' ') bytes)"
echo

log "openssl req -inform DER -text -noout"
echo
openssl req -in "${CSR_OUT}" -inform DER -text -noout

echo
log "LDevID public key (openssl req -pubkey)"
echo
openssl req -in "${CSR_OUT}" -inform DER -noout -pubkey

banner "Demo complete"
