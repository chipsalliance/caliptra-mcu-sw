#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
#
# Shell script to run end-to-end attestation tests locally.
# This mirrors the jobs from .github/workflows/attestation.yml.
#
# Required env vars:
#   SPDM_VALIDATOR_DIR  - path to the spdm-emu build/bin directory
#
# Optional env vars:
#   WORKSPACE           - repo root (defaults to caliptra-mcu-sw under this script's directory)
#   DEMO_MODE           - set to 1 to pause between phases for a live demo
#   SKIP_BUILD          - set to 1 to skip Pre-Stage (firmware build)
#   SPDM_DUMP_DIR       - path to spdm_dump binary directory (for pcap transaction log)
#   SAFE_REPORT_GEN_DIR  - path to directory containing the SAFE endorsement generation script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-$SCRIPT_DIR}"
DEMO_MODE="${DEMO_MODE:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"

# ── Helper functions ───────────────────────────────────────────────────────────
# ANSI color codes (disabled when output is not a terminal)
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_GREEN='\033[32m'
    C_YELLOW='\033[33m'
    C_CYAN='\033[36m'
    C_RED='\033[31m'
    C_MAGENTA='\033[35m'
else
    C_RESET='' C_BOLD='' C_GREEN='' C_YELLOW='' C_CYAN='' C_RED='' C_MAGENTA=''
fi

info()  { echo -e "${C_CYAN}==>${C_RESET} $*"; }
error() { echo -e "${C_RED}ERROR:${C_RESET} $*" >&2; exit 1; }

check_command() {
    command -v "$1" >/dev/null 2>&1 || error "'$1' is not installed. Please install it first."
}

phase_banner() {
    local phase_label="$1"
    local phase_title="$2"
    echo ""
    echo -e "${C_BOLD}╔══════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}║  ${phase_label}${phase_label:+: }${phase_title}${C_RESET}"
    echo -e "${C_BOLD}╚══════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

substage_banner() {
    local label="$1"
    local desc="$2"
    echo ""
    echo -e "${C_BOLD}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BOLD}│  ${label}${label:+: }${desc}${C_RESET}"
    echo -e "${C_BOLD}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"
}

demo_pause() {
    if [[ "$DEMO_MODE" == "1" ]]; then
        echo ""
        read -rp "  ▶ Press Enter to continue to the next phase..."
        echo ""
    fi
}

# ── Prerequisite checks (always run) ───────────────────────────────────────────
info "Checking prerequisites..."
for cmd in git cargo openssl cocli; do
    check_command "$cmd"
done

if [ -z "${SPDM_VALIDATOR_DIR:-}" ]; then
    error "SPDM_VALIDATOR_DIR environment variable is not set. Set it to the spdm-emu bin directory."
fi

if [ ! -d "$SPDM_VALIDATOR_DIR" ]; then
    error "SPDM_VALIDATOR_DIR does not exist: $SPDM_VALIDATOR_DIR"
fi

export SPDM_VALIDATOR_DIR

CORIM_DIR="$WORKSPACE/attestation-artifacts/refval-corim"

if [[ "$SKIP_BUILD" != "1" ]]; then
# ══════════════════════════════════════════════════════════════════════════════
# Pre-Stage: Prerequisites & Firmware Build
# ══════════════════════════════════════════════════════════════════════════════
phase_banner "Pre-Stage" "Prerequisites & Firmware Build"

FEATURE="test-mctp-spdm-attestation"
BUILD_LOG="/tmp/attestation-build.log"
info "Building firmware with feature '${FEATURE}'..."
info "  (full log: $BUILD_LOG)"
pushd "$WORKSPACE" >/dev/null
cargo xtask all-build --runtime-features "$FEATURE" 2>&1 | tee "$BUILD_LOG" | grep -E '(Compiling|error\[)' || true
popd >/dev/null

CORIM_CONFIG="/tmp/corim-config.json"
cat > "$CORIM_CONFIG" << 'EOF'
{
  "output_dir": "attestation-artifacts/refval-corim",
  "signing": {
    "test_key": "caliptra-corim-test-signing-key"
  }
}
EOF

CORIM_LOG="/tmp/attestation-corim-gen.log"
info "Generating reference-value CoRIM from firmware bundle..."
pushd "$WORKSPACE" >/dev/null
cargo xtask corim gen-refval --bundle target/all-fw.zip --config "$CORIM_CONFIG" 2>&1 | tee "$CORIM_LOG" | grep -E '(error|warning\[)' || true
popd >/dev/null

# Generate SAFE endorsement CoRIMs (if SAFE_REPORT_GEN_DIR is set)
ENDORSEMENT_SRC_DIR="$WORKSPACE/attestation-artifacts/safe_endorsements"
SAFE_LOG="/tmp/attestation-safe-gen.log"
if [ -n "${SAFE_REPORT_GEN_DIR:-}" ]; then
    SAFE_SCRIPT="$SAFE_REPORT_GEN_DIR/gen_endorsement_corim.sh"
    if [ -x "$SAFE_SCRIPT" ]; then
        info "Generating SAFE endorsement CoRIMs via ${C_CYAN}${SAFE_SCRIPT}${C_RESET}..."
        "$SAFE_SCRIPT" "$ENDORSEMENT_SRC_DIR" > "$SAFE_LOG" 2>&1 || true
    else
        info "${C_YELLOW}⚠${C_RESET} gen_endorsement_corim.sh not found — using pre-existing endorsement artifacts."
    fi
fi



info "${C_GREEN}✔${C_RESET} Pre-Stage complete: firmware built, CoRIMs generated."
demo_pause

fi  # end SKIP_BUILD

[[ -f "$WORKSPACE/target/all-fw.zip" ]] || error "target/all-fw.zip not found — run without SKIP_BUILD first."

# ══════════════════════════════════════════════════════════════════════════════
# Stage 0: Trust Anchor Store
#   Assemble trusted CA certs & CoRIM signing certs
# ══════════════════════════════════════════════════════════════════════════════
phase_banner "Stage 0" "Trust Anchor Store"

rm -rf "$WORKSPACE/attestation-artifacts/ta_store"

TA_STORE_DIR="$WORKSPACE/attestation-artifacts/ta_store"
mkdir -p "$TA_STORE_DIR/roots" "$TA_STORE_DIR/signing-certs"

info "Set up roots/ — trusted CA certificates for authenticating device identity..."
# Copy the test root CA cert which endorsed the device ID cert into roots/
cp "$WORKSPACE/ocp-eat-verifier/ocptoken-rs/test-data/ta-store/roots/slot0_ecc_test_root_ca.der" \
  "$TA_STORE_DIR/roots/slot0_ecc_test_root_ca.der"
cp "$CORIM_DIR/fake_keys/signing-cert.der" "$TA_STORE_DIR/roots/refval_corim_signing_cert.der"

info "Set up signing-certs/ — CoRIM signing certificates for verifying reference value integrity..."
# Copy the CoRIM signing certificate into signing-certs/
cp "$CORIM_DIR/fake_keys/signing-cert.der" "$TA_STORE_DIR/signing-certs/refval_corim_signing_cert.der"

# If endorsement CoRIMs exist, add their signing cert to roots/ and signing-certs/
ENDORSEMENT_CERT_SRC="$WORKSPACE/attestation-artifacts/safe_endorsements"
if [ -f "$ENDORSEMENT_CERT_SRC/testkey_p384_cert.der" ]; then
    cp "$ENDORSEMENT_CERT_SRC/testkey_p384_cert.der" "$TA_STORE_DIR/roots/endorsement_corim_signing_cert.der"
    cp "$ENDORSEMENT_CERT_SRC/testkey_p384_cert.der" "$TA_STORE_DIR/signing-certs/endorsement_corim_signing_cert.der"
fi

# info "Trust Anchor Store:"
# tree -n "${TA_STORE_DIR#$WORKSPACE/}" | sed "s/[^ ]*\.[^ ]*$/$(echo -ne "$C_GREEN")&$(echo -ne "$C_RESET")/"

echo -ne "${C_RESET}"
info "${C_GREEN}✔${C_RESET} Trust Anchor Store is ready."
demo_pause

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: Provisioning
#   1a: Provision pre-built reference-value CoRIMs (generated in Pre-Stage)
#   1b: Provision pre-built endorsement CoRIMs (generated in Pre-Stage)
# ══════════════════════════════════════════════════════════════════════════════
phase_banner "Stage 1" "Provisioning"

# ── Stage 1a: Provision Reference Values ─────────────────────────────────────
substage_banner "Stage 1a" "Provision Reference Values"

rm -rf "$WORKSPACE/attestation-artifacts/signed_refval_corims"
SIGNED_CORIM_DIR="$WORKSPACE/attestation-artifacts/signed_refval_corims"
mkdir -p "$SIGNED_CORIM_DIR"

if ls "$CORIM_DIR"/vendor-signed-*.cbor >/dev/null 2>&1; then
    cp "$CORIM_DIR"/vendor-signed-*.cbor "$SIGNED_CORIM_DIR/"
    for f in "$SIGNED_CORIM_DIR"/*.cbor; do
        echo -e "  Signed CoRIM:          ${C_CYAN}${f#$WORKSPACE/}${C_RESET}"
    done
else
    info "${C_YELLOW}⚠${C_RESET} No signed refval CoRIMs found in ${CORIM_DIR#$WORKSPACE/} — skipping."
fi

# Copy signing cert into Trust Anchor Store
if [ -f "$CORIM_DIR/fake_keys/signing-cert.der" ]; then
    cp "$CORIM_DIR/fake_keys/signing-cert.der" "$TA_STORE_DIR/roots/refval_corim_signing_cert.der"
    cp "$CORIM_DIR/fake_keys/signing-cert.der" "$TA_STORE_DIR/signing-certs/refval_corim_signing_cert.der"
fi

info "${C_GREEN}✔${C_RESET} Stage 1a complete: reference values provisioned."

# ── Stage 1b: Provision Endorsements ─────────────────────────────────────────
substage_banner "Stage 1b" "Provision Endorsements"

ENDORSEMENT_SRC_DIR="$WORKSPACE/attestation-artifacts/safe_endorsements"
SIGNED_ENDORSEMENT_DIR="$WORKSPACE/attestation-artifacts/signed_endorsement_corims"
rm -rf "$SIGNED_ENDORSEMENT_DIR"
mkdir -p "$SIGNED_ENDORSEMENT_DIR"

if [ -d "$ENDORSEMENT_SRC_DIR" ] && ls "$ENDORSEMENT_SRC_DIR"/*.cbor >/dev/null 2>&1; then
    # Copy signed endorsement CoRIMs
    cp "$ENDORSEMENT_SRC_DIR"/*.cbor "$SIGNED_ENDORSEMENT_DIR/"
    for f in "$SIGNED_ENDORSEMENT_DIR"/*.cbor; do
        echo -e "  Signed CoRIM:          ${C_MAGENTA}${f#$WORKSPACE/}${C_RESET}"
    done

    # Copy endorsement signing cert into Trust Anchor Store
    if [ -f "$ENDORSEMENT_SRC_DIR/testkey_p384_cert.der" ]; then
        cp "$ENDORSEMENT_SRC_DIR/testkey_p384_cert.der" \
          "$TA_STORE_DIR/roots/endorsement_corim_signing_cert.der"
        cp "$ENDORSEMENT_SRC_DIR/testkey_p384_cert.der" \
          "$TA_STORE_DIR/signing-certs/endorsement_corim_signing_cert.der"
    fi

    info "${C_GREEN}✔${C_RESET} Stage 1b complete: endorsements provisioned."
else
    info "${C_YELLOW}⚠${C_RESET} No endorsement CoRIMs found in ${ENDORSEMENT_SRC_DIR#$WORKSPACE/} — skipping."
fi

echo ""
info "${C_GREEN}✔${C_RESET} Stage 1 complete: all provisioning finished."
demo_pause

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: Acquire Evidence from Attester (SPDM Attestation)
#   — The verifier challenges the attester and collects fresh evidence.
# ══════════════════════════════════════════════════════════════════════════════
phase_banner "Stage 2" "Acquire Evidence from Attester"

info "Generating SPDM nonce..."
export SPDM_NONCE
SPDM_NONCE="$(openssl rand -hex 32)"
echo -e "SPDM_NONCE: \033[1;38;2;178;34;34m${SPDM_NONCE}\033[0m"

SPDM_TEST_LOG="/tmp/attestation-spdm-test.log"
info "Running SPDM attestation on MCTP transport..."
info "  (full log: $SPDM_TEST_LOG)"
pushd "$WORKSPACE" >/dev/null
cargo t -p tests-integration -- --test test_mctp_spdm_attestation --nocapture --include-ignored 2>&1 | tee "$SPDM_TEST_LOG" | grep -Ev 'no prebuilt available|process binary in flash|caliptra-okref|MCTP-SPDM-RESPONDER-VALIDATOR' | grep -E '(ok|FAILED|PASS|verify_measurement|SPDM_TASK|SPDM main)' || true
popd >/dev/null

info "Attestation artifacts available:"
for f in measurement_block_fd.bin certificate_chain_slot_00.der; do
    if [ -f "$SPDM_VALIDATOR_DIR/$f" ]; then
        echo -e "  ${C_GREEN}[found]${C_RESET} \033[1;38;2;178;34;34m$f\033[0m"
    else
        echo -e "  ${C_RED}[missing]${C_RESET} $f"
    fi
done

demo_pause

SPDM_DUMP_DIR="${SPDM_DUMP_DIR:-$SPDM_VALIDATOR_DIR}"
if [ -f "$SPDM_VALIDATOR_DIR/caliptra-evidence.pcap" ]; then
    info "Dumping SPDM transaction log (caliptra-evidence.pcap)..."
    if [ -x "$SPDM_DUMP_DIR/spdm_dump" ]; then
        "$SPDM_DUMP_DIR/spdm_dump" -r "$SPDM_VALIDATOR_DIR/caliptra-evidence.pcap" 2>&1 || true
    else
        info "  (spdm_dump not found in $SPDM_DUMP_DIR — set SPDM_DUMP_DIR to enable pcap dump)"
    fi
fi

EVIDENCE_DIR="$WORKSPACE/attestation-artifacts/evidence"
rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"
cp "$SPDM_VALIDATOR_DIR/measurement_block_fd.bin" "$EVIDENCE_DIR/"
cp "$SPDM_VALIDATOR_DIR/certificate_chain_slot_00.der" "$EVIDENCE_DIR/"

info "${C_GREEN}✔${C_RESET} Stage 2 complete: evidence acquired from Attester."
demo_pause

# ══════════════════════════════════════════════════════════════════════════════
# Verifier Inputs Summary
# ══════════════════════════════════════════════════════════════════════════════
phase_banner "" "Verifier Inputs Summary"

info "Verifier inputs:"
echo ""
# echo -e "  ${C_GREEN}Trust Anchor Store:\033[0m"
# tree -n "${TA_STORE_DIR#$WORKSPACE/}" | sed "s/[^ ]*\.[^ ]*$/$(echo -ne "$C_GREEN")&$(echo -ne "$C_RESET")/" | sed 's/^/    /'
# echo ""
echo -e "  ${C_CYAN}Signed Reference Value CoRIMs:\033[0m"
tree -n "${SIGNED_CORIM_DIR#$WORKSPACE/}" | sed "s/[^ ]*\.[^ ]*$/$(echo -ne "$C_CYAN")&$(echo -ne "$C_RESET")/" | sed 's/^/    /'
echo ""
if [ -d "$SIGNED_ENDORSEMENT_DIR" ] && ls "$SIGNED_ENDORSEMENT_DIR"/*.cbor >/dev/null 2>&1; then
    echo -e "  ${C_MAGENTA}Signed Endorsement CoRIMs:\033[0m"
    tree -n "${SIGNED_ENDORSEMENT_DIR#$WORKSPACE/}" | sed "s/[^ ]*\.[^ ]*$/$(echo -ne "$C_MAGENTA")&$(echo -ne "$C_RESET")/" | sed 's/^/    /'
    echo ""
fi
echo -e "  \033[1;38;2;178;34;34mEvidence (OCP EAT & cert chain):\033[0m"
tree -n "${EVIDENCE_DIR#$WORKSPACE/}" | sed "s/[^ ]*\.[^ ]*$/$(echo -ne '\033[1;38;2;178;34;34m')&$(echo -ne '\033[0m')/" | sed 's/^/    /'
echo ""

info "${C_GREEN}✔${C_RESET} All verifier inputs ready."
demo_pause

# ══════════════════════════════════════════════════════════════════════════════
# Appraisal Pipeline — OCP EAT Verifier Algorithm  (handled by ocptoken)
#
# The ocptoken 'appraise' subcommand runs the OCP EAT Verifier Algorithm:
#   Phase 1: Input Validation & Transformation  — authenticate evidence & CoRIMs
#   Phase 2: Evidence Augmentation              — decode EAT claims and initialize appraisal context
#   Phase 3: Reference Values Corroboration     — match ref-vals against evidence
#   Phase 5: Verifier Augmentation              — nonce freshness & debug status
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${C_BOLD}${C_MAGENTA}╔══════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_BOLD}${C_MAGENTA}║  Execute OCP EAT Verifier Algorithm ${C_RESET}"
echo -e "${C_BOLD}${C_MAGENTA}╚══════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""

info "Building OCP EAT Verifier (ocptoken)..."
pushd "$WORKSPACE/ocp-eat-verifier" >/dev/null
cargo build --release -p ocptoken 2>&1 | grep -E '(error\[)' || true
popd >/dev/null

info "Running appraisal pipeline..."
export TA_STORE_PATH="$TA_STORE_DIR"
export SIGNED_REFVAL_CORIM_PATH="$SIGNED_CORIM_DIR"

if [ -d "$SIGNED_ENDORSEMENT_DIR" ] && ls "$SIGNED_ENDORSEMENT_DIR"/*.cbor >/dev/null 2>&1; then
    export SIGNED_ENDORSEMENT_CORIM_PATH="$SIGNED_ENDORSEMENT_DIR"
    info "Endorsement CoRIMs: ${C_CYAN}${SIGNED_ENDORSEMENT_DIR}${C_RESET}"
fi

DEMO_FLAG=""
if [[ "$DEMO_MODE" == "1" ]]; then
    DEMO_FLAG="--demo"
fi

pushd "$WORKSPACE/ocp-eat-verifier" >/dev/null
./target/release/ocptoken appraise \
  -e "$EVIDENCE_DIR/measurement_block_fd.bin" \
  -c "$EVIDENCE_DIR/certificate_chain_slot_00.der" \
  $DEMO_FLAG
popd >/dev/null

echo -e "\n${C_BOLD}${C_GREEN}==> End-to-end attestation completed successfully.${C_RESET}\n"
