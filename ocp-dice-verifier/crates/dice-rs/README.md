# dice-rs

`dice-rs` is a pure Rust implementation of the [TCG DICE Attestation Architecture](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf) (v1.1, v1.2+).

It provides evidence extraction and decoding for TCG DICE certificate extensions, designed with a clean architecture that is compatible with Veraison DICE models. Downstream chain validation, trust anchor management, and reference value appraisal are handled by the verifier / appraisal layer.

## Supported Specifications

- **TCG DICE Attestation Architecture Specification Version 1.2**
- **TCG DICE Certificate Profiles (X.509)**
- **TCG Guidance for Securing Device Identity (DICE / RIoT)**

## Supported OIDs

| Name | OID | ASN.1 Type | Purpose |
| :--- | :--- | :--- | :--- |
| `tcg-dice-TcbInfo` | `2.23.133.5.4.1` | `DiceTcbInfo` | Single layer TCB measurements |
| `tcg-dice-MultiTcbInfo` | `2.23.133.5.4.5` | `SEQUENCE OF DiceTcbInfo` | Composite/multi-component TCB measurements |
| `tcg-dice-Ueid` | `2.23.133.5.4.4` | `DiceUeid` | Universal Entity Identifier (device/context ID) |
| `tcg-dice-kp-identityInit` | `2.23.133.5.4.100.6` | EKU KeyPurposeId | Initial Device Identity (IDevID) |
| `tcg-dice-kp-identityLoc` | `2.23.133.5.4.100.7` | EKU KeyPurposeId | Local Device Identity (LDevID) |
| `tcg-dice-kp-attestInit` | `2.23.133.5.4.100.8` | EKU KeyPurposeId | Initial Attestation Key |
| `tcg-dice-kp-attestLoc` | `2.23.133.5.4.100.9` | EKU KeyPurposeId | Local Attestation Key (Alias / DPE Leaf) |
| `tcg-dice-kp-assertInit` | `2.23.133.5.4.100.10`| EKU KeyPurposeId | Initial Assertion Key |
| `tcg-dice-kp-assertLoc` | `2.23.133.5.4.100.11`| EKU KeyPurposeId | Local Assertion Key |
| `tcg-dice-kp-eca` | `2.23.133.5.4.100.12`| EKU KeyPurposeId | Embedded Certificate Authority |

## ASN.1 Schema (TCG DICE v1.2)

```asn1
DiceTcbInfo ::= SEQUENCE {
    vendor              [0] IMPLICIT UTF8String OPTIONAL,
    model               [1] IMPLICIT UTF8String OPTIONAL,
    version             [2] IMPLICIT UTF8String OPTIONAL,
    svn                 [3] IMPLICIT INTEGER OPTIONAL,
    layer               [4] IMPLICIT INTEGER OPTIONAL,
    index               [5] IMPLICIT INTEGER OPTIONAL,
    fwids               [6] IMPLICIT FWIDLIST OPTIONAL,
    flags               [7] IMPLICIT OperationalFlags OPTIONAL,
    vendorInfo          [8] IMPLICIT OCTET STRING OPTIONAL,
    type                [9] IMPLICIT OCTET STRING OPTIONAL,
    operationalFlagsMask[10] IMPLICIT OperationalFlags OPTIONAL,
    integrityRegisters  [11] IMPLICIT IntegrityRegisters OPTIONAL
}

FWIDLIST ::= SEQUENCE SIZE (1..MAX) OF Fwid

Fwid ::= SEQUENCE {
    hashAlg             OBJECT IDENTIFIER,
    digest              OCTET STRING
}

DiceMultiTcbInfo ::= SEQUENCE SIZE (1..MAX) OF DiceTcbInfo

DiceUeid ::= SEQUENCE {
    ueid                OCTET STRING
}
```

## Features

- **`std` (default):** Enables standard library integration, including `x509-parser` helper utilities for extracting DICE extensions from raw certificates.
- **`alloc`:** Enables memory allocation for environments without standard library (`no_std` with allocator).

## License

Licensed under the Apache License, Version 2.0 (Apache-2.0).
