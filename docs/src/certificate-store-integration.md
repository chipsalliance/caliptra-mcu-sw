# Certificate Store Integration

## Purpose

This guide describes how a platform integrator configures the Caliptra MCU
certificate store.

## Implementation status

This guide defines the target release integration contract. The current source
tree does not yet provide every interface or capability described below.

| Status | Capability |
| --- | --- |
| Implemented | ECC P-384 Vendor certificate-chain retrieval through SPDM using the current `SharedCertStore` |
| Test-only | SPDM managed Owner and Tenant slots enabled by `test-mctp-spdm-set-certificate`; this path does not provide production authorization |
| Planned | Common certificate-store initialization, the Vendor IDevID certificate provider, ML-DSA-87 certificate chains, MCI certificate commands, and configurable Tenant SlotIDs |
| Deferred | Production managed-slot authorization and backing contracts |

Names identified as proposed in this guide describe intended interfaces. They
are not current Rust APIs.

Before integrating the store, review:

- [Caliptra Certificate Model](./certificate_model.md) for the trust model,
  endorsement roles, certificate algorithms, and chain composition.
- [Caliptra MCU Certificate Store](./cert_store.md) for the normative
  certificate-store behavior.
- [In-field Certificate Provisioning and
  Management](./certificate_provisioning.md) for the Owner and Tenant
  lifecycle.

SPDM message formats are defined by the SPDM specifications. MCI certificate
command codes are reserved in [External Mailbox
Commands](./external_mailbox_cmds.md), but their formats and implementation
are planned.

## Integration sequence

The proposed release integration sequence is:

1. [Define the static platform certificate-store
   profile](#define-the-platform-profile).
2. [Select the global certificate algorithm
   profile](#select-the-certificate-algorithm-profile).
3. [Select the PKI anchor point for each enabled managed
   slot](#select-pki-anchor-points).
4. [Configure the Vendor slot](#vendor-slot), including the Vendor CA
   certificates and the proposed `VendorIdevidCertificateProvider`.
5. [Set the maximum stored endorsement size and allocate persistent
   backing](#configure-managed-endorsement-backing).
6. [Connect the certificate and signing
   services](#connect-certificate-and-signing-services).
7. Configure [SPDM](#configure-spdm-exposure) and planned
   [MCI](#planned-mci-exposure) exposure.
8. [Configure the certificate provisioning authorization
   policy](#configure-authorization).
9. [Initialize the certificate
   store](#proposed-common-certificate-store-initialization) before starting
   responder tasks.
10. [Validate every enabled certificate path](#validate-the-integration).

## Define the platform profile

The proposed release design defines one static certificate-store profile and
passes it to the proposed `cert_store::initialize(...)` API. The profile is
fixed for the lifetime of the initialized store.

| Area | Platform profile supplies | Resulting certificate-store behavior |
| --- | --- | --- |
| Slot enablement | Whether the Owner and Tenant certificate slots are enabled | The Vendor slot is mandatory; the Owner and Tenant slots are optional |
| Certificate algorithm profile | ECC P-384 only, or ECC P-384 plus ML-DSA-87 | Every enabled slot is configured to support every algorithm selected by the profile; each algorithm-and-slot chain initializes independently |
| PKI anchor point | The permitted Caliptra device key for Owner and Tenant | Vendor uses the manufacturing IDevID; provisioning cannot select a different key |
| Vendor endorsement | Vendor Root and optional intermediate CA certificates, plus the proposed `VendorIdevidCertificateProvider` for each profile algorithm | The Vendor slot is manufacturing-provisioned and read-only |
| Owner endorsement | Maximum stored PKI endorsement size and persistent backing for each profile algorithm | The Owner slot is managed and requires authorization |
| Tenant endorsement | Enablement, PKI anchor point, maximum stored PKI endorsement size, persistent backing, and SPDM SlotID policy | Tenant remains independent from Vendor and Owner |

### Select the certificate algorithm profile

ML-DSA-87 certificate-chain support is planned. The certificate algorithm
profile remains independent of the configured SPDM protocol version. Enabling
SPDM 1.4 does not automatically enable ML-DSA-87. Once implemented, SPDM will
expose ML-DSA-87 only when the classical-plus-PQC profile is selected and the
transport supports its negotiation.

The Vendor ECC P-384 chain must be provisioned for certificate-store
initialization to succeed. When the classical-plus-PQC profile is selected,
the Vendor ML-DSA-87 chain is configured independently and remains unavailable
if it cannot be initialized.

### Select PKI anchor points

The PKI anchor point is the Caliptra identity key certified by the endorsing
PKI:

- The Vendor slot always uses the manufacturing IDevID.
- The Owner slot uses the LDevID by default.
- The Tenant slot uses the Caliptra identity key selected by the platform
  profile.

The selected key must be supported by the generated certificate and signing
services. Provisioning supplies certificates for the selected key; it does
not select or replace the key. See [Supporting multiple PKI
owners](./certificate_model.md#supporting-multiple-pki-owners) for the PKI
anchor-point model.

### Initialization and chain availability

Each configured algorithm-and-slot chain initializes independently.

- Failure to initialize the mandatory Vendor ECC P-384 chain causes common
  certificate-store initialization to fail.
- Failure to initialize any other configured chain leaves only that chain
  unavailable. The failure is reported for platform diagnostics.
- A managed chain with accessible backing but no committed endorsement is
  unprovisioned, not failed.
- Unavailable and unprovisioned chains are not advertised as provisioned by
  any transport.

Examples of nonfatal per-chain failures include an unsupported PKI anchor
point, unavailable certificate or signing capability, an inaccessible backing
region, or failure to obtain a nonmandatory Vendor ML-DSA-87 certificate.

## Configure certificate slots

### Vendor slot

For the Vendor slot:

- Embed the Vendor Root CA and optional intermediate CA certificates in the
  MCU Runtime user application image.
- Implement the proposed `VendorIdevidCertificateProvider` to supply the
  complete signed IDevID certificate for every algorithm selected by the
  global profile.
- Do not allocate managed writable backing for Vendor.

The Vendor endorsement certificates are established during manufacturing and
remain read-only for the device lifetime. Runtime authorization cannot
provision, replace, or remove them.

The planned provider contract allows a platform implementation to return a
complete provisioned certificate or assemble it using certificate data from
the MCU Runtime user application image, External OTP, or both. In every case,
the provider will return a complete DER certificate to the proposed common
certificate-store initialization path.

### Owner slot

For the Owner slot, configure:

- Select the permitted Caliptra PKI anchor-point key.
- Set the maximum stored PKI endorsement size, in bytes, for each enabled
  profile algorithm.
- Assign independent managed persistent backing for each enabled profile
  algorithm.

The default Owner PKI anchor point is the Caliptra LDevID.

### Tenant slot

For the Tenant slot, configure:

- Select the permitted Caliptra PKI anchor-point key.
- Set the maximum stored PKI endorsement size, in bytes, for each enabled
  profile algorithm.
- Assign independent managed persistent backing for each enabled profile
  algorithm.
- Configure the SPDM Tenant SlotID policy.

Tenant is optional and remains independent from Vendor and Owner.
Configurable Tenant SlotIDs are planned. The current implementation uses the
fixed mapping Vendor Slot 0, Owner Slot 2, and Tenant Slot 3.

## Connect certificate and signing services

No separate integrator-facing certificate or signing provider interface
exists in the current source tree. The following requirements describe the
planned release ownership boundary.

Connect each algorithm selected by the global profile to the SDK services
that supply:

- Caliptra device certificates below the configured PKI anchor point.
- The generated DPE leaf certificate.

The corresponding SDK signing service performs the private-key operation for
the generated leaf certificate. Private keys remain protected by Caliptra and
are not stored in the certificate store.

Connect the certificate and signing services to the same identity lifecycle
so the complete chain and signing operation refer to the same active leaf
identity.

An algorithm-specific certificate chain is available only when the platform
can provide:

- The complete endorsement.
- The complete generated certificate path.
- The generated leaf certificate.
- The matching signing operation.

## Configure managed endorsement backing

The production managed-backing interface and sizing contract are deferred to
later work. The current flash-backed managed path is test-only and is not a
production storage contract. The following requirements describe the target
release behavior.

Assign platform persistent storage to every enabled managed
algorithm-and-slot endorsement. Configure the maximum stored PKI endorsement
size, in bytes. The assigned region may require additional space for
certificate-store metadata and atomic updates.

The storage assignment must:

- Accommodate the configured maximum endorsement size.
- Keep ECC P-384 and ML-DSA-87 chains independent.
- Keep Owner and Tenant chains independent.
- Be accessible during certificate-store initialization.
- Remain available for the lifetime of the initialized store.

Do not overlap backing assigned to different certificate keys.

The certificate store owns its persistent record format, atomic publication,
and recovery behavior. The platform integration does not define those
mechanisms.

## Configure SPDM exposure

The `SpdmPalCertStore` implementation uses these slot mappings:

| Certificate slot | SPDM SlotID mapping |
| --- | --- |
| Vendor | Slot 0 |
| Owner | Slot 2 |
| Tenant | Slot 3 currently; requester-selected from integrator-configured eligible SlotIDs is planned |

The current implementation uses the fixed slot map `[0, 2, 3]`. The proposed
configuration allows other unallocated SPDM SlotIDs to become eligible for
Tenant assignment. When both SPDM and MCI certificate access are implemented,
the profile will also select which eligible SPDM SlotID represents a Tenant
endorsement first provisioned through MCI.

`SpdmPalCertStore` derives its certificate capabilities from the common
certificate-store configuration. The integrator does not implement a separate
SPDM certificate store.

## Planned MCI exposure

MCI certificate-chain access is planned. The command codes are reserved, but
the handlers and request and response formats are not implemented.

The planned commands identify the certificate algorithm and
`EndorsementRole` directly and do not use SPDM SlotIDs. The planned MCI mailbox
handler will access the same common certificate-store state as SPDM.

`MC_GET_CERT_CHAIN` is reserved for complete-chain retrieval, and
`MC_SET_CERT_CHAIN` is reserved for authorized endorsement updates. Their
future request and response formats belong in [External Mailbox
Commands](./external_mailbox_cmds.md).

## Configure authorization

Production certificate provisioning authorization is deferred to later work.
The existing SPDM managed-slot path is test-only and authorizes a request only
by checking whether the target slot is writable. Production Owner and Tenant
provisioning must not be enabled until the common authorization contract is
defined and implemented.

The authorization policy defines:

- Specify which requester credentials are accepted.
- Specify which managed certificate slots each requester can manage.
- Specify which certificate algorithms are permitted.
- Specify which PKI anchor-point key is authorized.
- Specify whether the requester can provision, replace, or remove an
  endorsement.

SPDM and MCI carry the same authorization message and signed content. Only
their outer transport framing differs.

The Vendor slot remains read-only regardless of the configured authorization
credentials.

The production credential format, policy profile, and credential lifecycle
are defined separately from this guide. See the [Authorization
model](./certificate_provisioning.md#authorization-model) for the common SPDM
and MCI authorization requirements.

## Proposed common certificate-store initialization

The current implementation initializes `SharedCertStore` from the SPDM module.
The target release design moves this ownership into a protocol-neutral
certificate-store module.

During user application startup, the proposed
`cert_store::initialize(...)` API will be called from the `boot_init()` path
before starting any SPDM or MCI responder task. The proposed API will:

1. Apply the platform certificate profile.
2. Load the Vendor Root and intermediate certificates from the MCU Runtime
   user application image.
3. Obtain the complete IDevID certificate for each provisioned algorithm from
   the proposed `VendorIdevidCertificateProvider`.
4. Connect the configured generated-certificate, signing, and persistent
   storage services.
5. Recover managed Owner and Tenant endorsements.
6. Determine which certificate chains are available.
7. Make the initialized store available to the `SpdmPalCertStore`
   implementation and MCI mailbox command handler.

The target release will start responder tasks only after the proposed
initialization API succeeds. It will not create transport-owned certificate
stores. Every enabled SPDM and MCI responder will use the same initialized
instance.

## Validate the integration

For each advertised algorithm-and-slot certificate chain:

1. Retrieve the complete chain through every transport configured to expose
   it.
2. Validate the chain from its expected PKI Root CA through the generated DPE
   leaf certificate.
3. Perform an attestation or signed challenge and verify it with the leaf
   certificate.
4. Confirm that all transports configured to expose the chain observe the
   same active endorsement after a managed update.

ML-DSA-87 and MCI validation apply after those planned capabilities are
implemented.

Confirm that an enabled but unprovisioned managed slot is not advertised.
Also verify that reset recovery exposes either the last complete committed
endorsement or an unprovisioned slot, never a partial replacement.

Before enabling certificate commands, confirm that:

- The Vendor ECC P-384 chain is provisioned.
- When the classical-plus-PQC profile is selected, an unavailable Vendor
  ML-DSA-87 chain is not advertised and its initialization failure is
  reported.
- Every advertised certificate chain has a matching signing operation.
- Vendor is read-only.
- Owner and Tenant use their configured PKI anchor-point keys.
- ECC P-384 and ML-DSA-87 use independent certificate paths and managed
  backing.
- Configured maximum endorsement sizes fit the permitted endorsement
  profiles.
- Persistent regions do not overlap.
- Tenant SlotID eligibility and, when required, the MCI-associated SlotID are
  configured.
- Configured chains that fail initialization remain unavailable.
- Managed chains with no committed endorsement remain unprovisioned.
- When both transports are enabled, SPDM and MCI use the same common store.
- When both transports support managed updates, SPDM and MCI use the same
  authorization content and policy.
- A replacement becomes visible only after successful validation and
  publication.
- Reset recovery produces either a complete committed endorsement or an
  unprovisioned state.
