# In-field Provisioning and Management of SPDM Certificate Slots
This document provides guidance for provisioning and managing certificate slots on Caliptra devices via the SPDM protocol, conforming to the [OCP Device Identity Provisioning Specification](https://opencomputeproject.github.io/Security/device-identity-provisioning/HEAD/).

Supporting the multiple PKI ownership model defined by OCP requires SPDM Responder to support multiple asymmetric key pairs in the connection (`MULTI_KEY_CONN_RSP` is true). Consequently, OCP Device Identity Provisioning features requires SPDM version 1.3 or later.


## Caliptra Device Identity Key Pairs Discovery
Caliptra device shall support the following 3 key pairs for certificate slot provisioning and management:
- `LDevID` Key Pair (SPDM  Key pair ID 1)
- `FMC Alias` Key Pair (SPDM Key pair ID 2)
- `RT Alias` Key Pair (SPDM Key pair ID 3)

The `IdevID` key pair is pre‑provisioned by the vendor in SPDM certificate slot 0 and is treated as non‑configurable by the implementation.

The information about these key pairs can be retrieved by issuing the `GET_KEY_PAIR_INFO` request. The SPDM responder sets the `GET_KEY_PAIR_INFO_CAP` capability bit to advertise support for `KEY_PAIR_INFO` response messages. The implementation does not allow the requester to modify any parameters associated with Caliptra key pairs; as a result, the `SET_KEY_PAIR_INFO_CAP` capability bit remains cleared.

## SPDM Certificate Slot mapping to OCP PKI entities
The default SPDM certificate slot mapping to OCP PKI entities is as follows:
- Slot 0: Vendor (pre-provisioned, fixed and read-only)
- Slot 1: Unused (available for future use)
- Slot 2: Owner (provisionable by Owner PKI)
- Slot 3: Tenant (provisionable by Tenant PKI)

But the actual mapping can be discovered by the SPDM Requester using the `OCP_GET_SLOT_ID_MAPPING` request.

## Provisioning workflows using SPDM protocol
It is assumed that the Vendor slot is pre‑provisioned and meets the SPDM requirements for initial device attestation. The Vendor slot may also be used to establish a secure session with the SPDM Requester (Owner/Tenant PKI) for subsequent certificate‑slot provisioning.

The following sequence diagram illustrates the workflow for provisioning Owner certificate slots using the SPDM protocol.

```mermaid
sequenceDiagram
    participant SPDMRequester as SPDM Requester/PKI Owner
    participant MCU as Caliptra MCU/SPDM Responder
    participant CaliptraRT
    Note over SPDMRequester,MCU: ...<br/> 1. Perform initial Device Attestation using Vendor Slot. <br/>The requester has the device identity certificates.<br/> ...
    opt 
        Note over SPDMRequester,MCU: 2. Retrieve Device Identity Key Pair Info
        SPDMRequester->>+MCU: GET_KEY_PAIR_INFO (KeyPairID:1 (LDevID))
        MCU->>-SPDMRequester: KEY_PAIR_INFO (TotalKeyPairs: 3, KeyPairID: 1, AssocCertSlotMask: 0x00)
    end
    opt 
        Note over SPDMRequester,MCU: 3. Discover SPDM Slot ID mapping for different OCP PKI entities
        SPDMRequester->>+MCU: OCP_GET_SLOT_ID_MAPPING
        MCU->>-SPDMRequester: OCP_SLOT_ID_MAPPING (Vendor:0, Owner: 2, Tenant:3)
    end
    Note over SPDMRequester,MCU: 4. Generate Envelope Signed CSR <br/> for key pair ID 1
    SPDMRequester->>+MCU: GET_ENVELOPE_SIGNED_CSR (KeyPairID: 1, Nonce: nonce)
    MCU->>+CaliptraRT: Request envelope signed LDevID CSR (nonce)
    CaliptraRT->>-MCU: Envelope signed LDevID CSR signed by RT alias key
    MCU->>-SPDMRequester: ENVELOPE_SIGNED_CSR (Envelope signed CSR data)
    SPDMRequester-->>SPDMRequester: Validate the CSR and <br/>Issue endorsement certificate for LDevID
    critical Within secure session and/or with requester authorization
        Note over SPDMRequester,MCU: 5. Complete Owner Slot Provisioning
        SPDMRequester->>+MCU: SET_CERTIFICATE (SlotID: 2, KeyPairID: 1, CertChain)
        MCU->>-SPDMRequester:SET_CERTIFICATE_RSP (SlotID: 2)
    end
    Note over SPDMRequester,MCU: 6. Verify Owner Slot Certificate Installation
    SPDMRequester->>+MCU: GET_KEY_PAIR_INFO (KeyPairID: 1)
    MCU->>-SPDMRequester: KEY_PAIR_INFO (TotalKeyPairs: 3, KeyPairID: 1, AssocCertSlotMask: 0x04)
    opt Get installed certificate chain and validate
        SPDMRequester->>+MCU: GET_CERTIFICATE (SlotID: 2)
        MCU->>-SPDMRequester: CERTIFICATE (SlotID: 2, CertChain)
        SPDMRequester-->>SPDMRequester: Validate the installed certificate chain
    end
    Note over SPDMRequester,MCU: ...<br/> 7. Perform attestation using the newly installed Owner slot
```
    
## Envelope-signed CSR generation
The MCU's SPDM responder supports retrieval of an envelope‑signed Certificate Signing Request (CSR) for a specified Device Identity Key-pair ID via the OCP vendor‑defined `GET_ENVELOPE_SIGNED_CSR` command. Upon receiving this request, the MCU forwards it to the Caliptra RT firmware, which generates the CSR and returns it encapsulated in an `EAT` (Entity Attestation Token). The `EAT` is signed using the `RT Alias` key pair. The `nonce` provided in the request is forwarded to the RT firmware and included in the EAT to ensure freshness.

## Authorization and Security Considerations
TBD