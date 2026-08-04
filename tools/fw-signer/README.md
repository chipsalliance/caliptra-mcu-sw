# Caliptra MCU Firmware Signer (`fw-signer`)

`fw-signer` is a command-line tool and Rust library for generating offline
authorization manifest signatures (`signatures.json`) from signing request
files (`signing_request.json`) in the Caliptra MCU software ecosystem.

It leverages `caliptra-image-gen` and `caliptra-image-crypto` to perform
cryptographic signing using either local PEM key files or Hardware Security
Modules (HSMs) via custom OpenSSL 3 Providers.

## Supported Cryptographic Algorithms

- **ECC P-384 (ECDSA)**: SHA-384 digests signed over NIST P-384 curves.
- **LMS (RFC 8554)**: Leighton-Micali Signatures for post-quantum security.
- **ML-DSA-87 (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm.

## Command-Line Usage

```bash
fw-signer \
  --signing-request /path/to/signing_request.json \
  --key-manifest /path/to/key_manifest.json \
  --output /path/to/signatures.json \
  [--openssl-provider <PROVIDER_NAME>]
```

### CLI Options

- `-r, --signing-request <PATH>`: Path to input `signing_request.json` file.
- `-k, --key-manifest <PATH>`: Path to JSON key manifest specifying key paths
  or OpenSSL provider key names.
- `-o, --output <PATH>`: Path to output `signatures.json` file.
- `--openssl-provider <NAME>`: Optional OpenSSL 3 provider name to load for
  cryptographic operations (e.g., `pkcs11`, `fips`, `default`).

## Key Manifest Schema (`key_manifest.json`)

The key manifest is a JSON file that configures signing keys for all four
authorization manifest signature targets: `vendor_fw`, `owner_fw`,
`vendor_man`, and `owner_man`.

Each component entry requires valid ECC P-384 and PQC key configurations.

### Example Key Manifest

```json
{
  "vendor_fw": {
    "ecc_priv_key": "path/to/vendor_ecc_priv.pem",
    "ecc_pub_key": "path/to/vendor_ecc_pub.pem",
    "pqc_priv_key": "path/to/vendor_lms_priv.pem",
    "pqc_pub_key": null,
    "pqc_type": "LMS"
  },
  "owner_fw": {
    "ecc_priv_key": "path/to/owner_ecc_priv.pem",
    "ecc_pub_key": "path/to/owner_ecc_pub.pem",
    "pqc_priv_key": "path/to/owner_mldsa_priv.pem",
    "pqc_pub_key": "path/to/owner_mldsa_pub.pem",
    "pqc_type": "MLDSA"
  },
  "vendor_man": {
    "ecc_priv_key": "path/to/vendor_man_ecc_priv.pem",
    "ecc_pub_key": "path/to/vendor_man_ecc_pub.pem",
    "pqc_priv_key": "path/to/vendor_man_lms_priv.pem",
    "pqc_pub_key": null,
    "pqc_type": "LMS"
  },
  "owner_man": {
    "ecc_priv_key": "path/to/owner_man_ecc_priv.pem",
    "ecc_pub_key": "path/to/owner_man_ecc_pub.pem",
    "pqc_priv_key": "path/to/owner_man_lms_priv.pem",
    "pqc_pub_key": null,
    "pqc_type": "LMS"
  }
}
```

### Key Manifest Fields

- `ecc_priv_key` (string): Local PEM file path or OpenSSL provider key URI.
- `ecc_pub_key` (string): Local PEM file path or OpenSSL provider key URI.
- `pqc_priv_key` (string): Local PEM file path or OpenSSL provider key URI.
- `pqc_pub_key` (string | null): Required when `pqc_type` is set to `MLDSA`.
- `pqc_type` (string): Must be either `"LMS"` or `"MLDSA"` (case-insensitive).

## OpenSSL Provider & HSM Integration

When `--openssl-provider <NAME>` is specified, `fw-signer` dynamically loads
the requested OpenSSL 3 provider (such as `pkcs11` for HSM access or `fips`
for FIPS-140 compliance).

When using an HSM provider, the key fields in `key_manifest.json` can be set
to PKCS#11 URIs or provider-specific key labels instead of filesystem paths:

```json
{
  "vendor_fw": {
    "ecc_priv_key": "pkcs11:token=MyHSM;object=vendor_ecc_key;type=private",
    "ecc_pub_key": "pkcs11:token=MyHSM;object=vendor_ecc_key;type=public",
    "pqc_priv_key": "pkcs11:token=MyHSM;object=vendor_lms_key;type=private",
    "pqc_pub_key": null,
    "pqc_type": "LMS"
  }
}
```

## End-to-End Workflow

1. **Generate Unsigned Manifest & Signing Request**:
   Use `cargo xtask auth-manifest create` to generate an unsigned auth
   manifest binary (`unsigned_manifest.bin`) and export the offline signing
   request (`signing_request.json`):
   ```bash
   cargo xtask auth-manifest create \
     --mcu_image mcu-runtime.bin,0xA8000000,0x60000000,2,2 \
     --output unsigned_manifest.bin \
     --signing-request signing_request.json \
     --vendor-fw-pub-key path/to/vendor_ecc_pub.pem \
     --owner-fw-pub-key path/to/owner_ecc_pub.pem
   ```

2. **Generate Offline Signatures**:
   Invoke `fw-signer` with your key manifest (`key_manifest.json`) to sign the
   digests in `signing_request.json` and generate `signatures.json`:
   ```bash
   fw-signer -r signing_request.json -k key_manifest.json -o signatures.json
   ```

3. **Attach Signatures**:
   Attach the resulting `signatures.json` to the unsigned authorization
   manifest using `cargo xtask auth-manifest attach-signatures`:
   ```bash
   cargo xtask auth-manifest attach-signatures \
     --unsigned-manifest unsigned_manifest.bin \
     --signatures signatures.json \
     --output signed_manifest.bin
   ```
