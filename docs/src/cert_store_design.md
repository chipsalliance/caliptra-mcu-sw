# SPDM Certificate Store Design

## Overview

This document describes the certificate store architecture for the Caliptra MCU SPDM responder. The cert store manages certificate chains for three SPDM certificate slots, each associated with an OCP PKI entity: **Vendor**, **Owner**, and **Tenant**.

For provisioning workflows, see [cert_slot_mgmt.md](cert_slot_mgmt.md). For the `SpdmCertStore` trait, see [spdm-integrator-guide.md](spdm-integrator-guide.md).

## Certificate Chain Composition

Each SPDM slot presents a complete certificate chain to the requester. The chain is composed of three independently-sourced portions, concatenated at read time:

```
  SPDM Certificate Chain (returned by GET_CERTIFICATE)
 ┌─────────────────────────────────────────────────────────────────┐
 │                                                                 │
 │  1. Endorsement Portion                                         │
 │     Root CA ──► Intermediate CA(s) ──► Endorsed Device Cert     │
 │                                                                 │
 │     Source: depends on slot (see below)                         |
 │                                                                 │
 ├─────────────────────────────────────────────────────────────────┤
 │                                                                 │
 │  2. Device Certificate Portion                                  │
 │     LDevID | FMC Alias | RT Alias                               │
 │     (depends on which device key the endorsement is             │
 │      anchored at)                                               │
 │                                                                 │
 │     Source: Caliptra Core (`GetCertificateChain` DPE command)   │
 │     Generated fresh from HW key hierarchy on every boot         │
 │                                                                 │
 ├─────────────────────────────────────────────────────────────────┤
 │                                                                 │
 │  3. DPE Leaf Certificate                                        │
 │     The actual signing key certificate                          │
 │                                                                 │
 │     Source: Caliptra Core (`CertifyKey` DPE command)            │
 │                                                                 │
 └─────────────────────────────────────────────────────────────────┘
```

- Only the **endorsement chain** (portion 1) differs between slots.
- The **device certificate chain** (portion 2) comes from Caliptra Core at runtime, read in chunks on demand.
- The **DPE leaf certificate** (portion 3) is fetched once from Caliptra Core and cached in memory for subsequent reads.

### Vendor Slot (SPDM slot_id: 0) — Pre-provisioned and Read only

```
  Vendor Endorsement Chain
 ┌─────────────────────────────────┬─────────────────────────────────────────┐
 │  Root CA ──► Intermediate CAs   │  Signed IDevID Certificate              │
 │                                 │                                         │
 │  Source: firmware .rodata       │  Source:                                │
 │  (by default)                   │    ECC: cert stored in OTP              │
 │                                 │    MLDSA: signature in OTP,             │
 │                                 │           cert template in .rodata      │
 └─────────────────────────────────┴─────────────────────────────────────────┘
```

This endorsement is **read-only** — `SET_CERTIFICATE` is rejected for slot 0.

### Managed Cert Slots (Owner / Tenant — SPDM slot_id > 0)

```
  Managed Endorsement Chain (written by SET_CERTIFICATE, cleared by erase)
 ┌──────────────────┬──────────────────────┬──────────────────────────────┐
 │  Root CA          │  Intermediate CA(s)  │  Endorsed Device Certificate │
 │  Certificate      │  (0 or more)         │  (trust anchor for the       │
 │                   │                      │   device identity key pair)  │
 │                   │                      │                              │
 │  Source: SPI flash partition, persisted by SET_CERTIFICATE (default)    │
 └──────────────────┴──────────────────────┴──────────────────────────────┘
```

The entire endorsement chain is provided by the SPDM requester via `SET_CERTIFICATE` and persisted to the SPI flash cert-store partition. For managed slots, the endorsement chain is established through the provisioning workflow:

1. The PKI entity selects an anchor point in the device certificate chain (e.g., LDevID or FMC Alias or RT Alias).
2. The PKI entity requests a CSR for the anchor device key using `GetAttestedCsr`, then authenticates and validates it.
3. The PKI entity endorses the CSR by signing it and provisions the full endorsement certificate chain (Root CA → Intermediates → Endorsed Device Cert) using the `SET_CERTIFICATE` command.

The device certificate portion and DPE leaf are common across all slots. For managed cert slots, the device certificate portion starts at the anchored device cert chain index corresponding to the `KeyPairID` (e.g., KeyPairID=1 anchors at LDevID, so the device cert portion includes LDevID → FMC Alias → RT Alias).

### Data Flow Summary

```
  GET_CERTIFICATE — reading cert chain in portions:

                     Endorsement               Device Cert            DPE Leaf
                     ───────────               ───────────            ────────
  Vendor (Slot 0):   .rodata + fuses           Caliptra Core          Caliptra Core
  Owner  (Slot 2):   SPI flash                 Caliptra Core          Caliptra Core
  Tenant (Slot 3):   SPI flash                 Caliptra Core          Caliptra Core
                          │                         │                       │
                          │                         │ (1 KB chunks          │ (cached in
                          │                         │  on demand)           │  memory)
                          │                         │                       │
                          └─────────┬───────────────┘                       │
                                    ▼                                       │
                     CertChain::read(offset, buf) ◄─────────────────────────┘
                                    │
                                    │
                                    ▼
                          GET_CERTIFICATE Response
                     (SPDM requester may call this
                      multiple times with offsets to
                      retrieve the full chain)


  SET_CERTIFICATE — writing endorsement to store:

                         SET_CERTIFICATE Request
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Parse SPDM CertChain envelope│
                    │  Extract: RootHash,           │
                    │           endorsement DER body │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  endorsement.write()         │
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                     ▼
  Vendor (Slot 0):          Owner (Slot 2):       Tenant (Slot 3):
  **REJECTED**              SPI flash             SPI flash
  (read-only)
```

**Notes:**

- Only the **endorsement chain** is written by `SET_CERTIFICATE`.
- The **device certificate chain** and **DPE leaf** are fetched live from Caliptra Core at read time; never persisted.
- Signing is always performed by the **DPE leaf key** via Caliptra, regardless of slot.

## Proposed DPE Command Changes

This section proposes changes to the `CertifyKey` and `GetCertificateChain` DPE commands to address two goals:

1. **Reduce memory overhead** — the current CertifyKey response requires large buffers on the MCU to hold the full leaf certificate.
2. **Return device certificates from the slot's anchor point** — each SPDM slot is anchored at a different device key, but the current GetCertificateChain always returns the full chain from IDevID. This requires the MCU to determine the correct offset for the anchor point within the device certificate chain, which adds complexity to handling the device portion.

### CertifyKey — Chunked Leaf Certificate

`CertifyKey` is extended in two ways:

1. The leaf certificate is provided in **chunks** rather than as a single large response, the same way the device cert chain is read today. This eliminates the need to buffer the entire leaf cert on the MCU.
2. The response is extended to also return the DPE leaf cert **size**, **thumbprint** (digest), and **derived public key** (needed for EAT).

### GetCertificateChain — Key-Index Parameter

`GetCertificateChain` will accept a `key_index` parameter so Caliptra returns only the relevant device certificates for a given slot.

- `key_index = 0` returns the full device chain from the start (IDevID → LDevID → FMC Alias → RT Alias), regardless of whether IDevID was populated.
- `key_index > 0` returns the device certs below the specified key.

For managed slots, the anchor cert is part of the endorsement portion (provisioned via `SET_CERTIFICATE`), so `GetCertificateChain` returns only what follows it.

| `key_index` | Slot Example | `GetCertificateChain` Returns |
|---|---|---|
| 0 (IDevID) | Vendor (Slot 0) | IDevID → LDevID → FMC Alias → RT Alias |
| 1 (LDevID) | Owner (Slot 2) | FMC Alias → RT Alias |
| 2 (FMC Alias) | Tenant (Slot 3) | RT Alias |
| 3 (RT Alias) | — | (empty — no device certs below RT Alias) |

This removes the need for the MCU to calculate offsets into the device chain.

### Impact on the Cert Store

- The three-portion model (endorsement → device certs → leaf cert) is preserved.
- Both the device cert portion and the leaf cert are now fetched in 1 KB chunks, streamed directly into the SPDM response.
- The full DPE leaf cert no longer needs to be cached in memory — only lightweight metadata (size + thumbprint) is retained.
- Signing is unaffected. The DPE `Sign` command does not depend on the cert buffer.
- Estimated memory savings: **~8 KB** (6.5 KB from the CertifyKey response buffer + 2 KB from the leaf cert cache).

