# Certificate Store Integration Guide

## Purpose

This guide describes how a platform integrator configures and integrates the
Caliptra MCU certificate store.

Before integrating the store, review:

- [Caliptra Certificate Model](./certificate_model.md) for the trust model,
  endorsement roles, certificate algorithms, and chain composition.
- [Caliptra MCU Certificate Store](./cert_store.md) for certificate-store design
  and behavioral requirements.
- [In-field Certificate Provisioning and Management](./certificate_provisioning.md)
  for Owner and Tenant endorsement lifecycles.
- [External Mailbox Commands](./external_mailbox_cmds.md) for MCI mailbox command
  definitions.

## Integration sequence

Integrate the certificate store through the following steps:

1. [Define the platform profile](#define-the-platform-profile) (algorithms, slots, PKI anchor points, and managed storage).
2. [Provide Vendor certificates](#provide-vendor-certificates) (Root CA and IDevID certificates).
3. [Configure transport exposure](#configure-transport-exposure) (SPDM and MCI).
4. [Configure authorization](#configure-authorization).
5. [Initialize the certificate store](#initialize-the-certificate-store) before starting responders.
6. [Validate the integration](#validate-the-integration).

## Define the platform profile

The platform profile defines static configuration for the lifetime of the
certificate store:

| Configuration | Platform selection | Behavior |
| --- | --- | --- |
| Algorithm profile | ECC P-384 only, or ECC P-384 plus ML-DSA-87 | ECC P-384 is always enabled; ML-DSA-87 is enabled when post-quantum support is configured. |
| Slot enablement | Enablement of Owner and Tenant slots | Vendor is always enabled and read-only. Owner and Tenant are optional managed slots. |
| PKI anchor points | Caliptra identity key certified by endorsements | Vendor binds to IDevID. Owner and Tenant can each be configured with a fixed key anchor point or left without a fixed key anchor point (in the default configuration, Owner uses LDevID and Tenant has no fixed key anchor point). |
| Endorsement backing | Storage allocation and size limits per managed role | Independent backing and size limits for each algorithm in Owner and Tenant. |

### Select the certificate algorithm profile

- **ECC P-384**: Mandatory and enabled for all active slots.
- **ML-DSA-87**: Configured when post-quantum support is required. When enabled,
  each active slot supports both ECC P-384 and ML-DSA-87 chains independently.

### Select PKI anchor points

The platform configures the static provisioning policy in the certificate store
for each managed role (Owner and Tenant):

- **Fixed key anchor point** (for example, Owner is configured with LDevID in
  the default policy): pins the role to that identity key. `key_pair_id = 0`
  resolves to the configured key anchor point, and any nonzero `key_pair_id`
  must match it.
- **No fixed key anchor point** (for example, Tenant in the default policy):
  allows any supported key anchor point when a nonzero `key_pair_id` is
  provided; `key_pair_id = 0` is rejected.

SPDM `SET_CERTIFICATE` passes `key_pair_id = 0` when the request has no
`KeyPairID` field (SPDM 1.2, or SPDM 1.3+ with `MULTI_KEY_CONN_RSP = 0`) and
passes the request's `KeyPairID` when `MULTI_KEY_CONN_RSP = 1`. MCI mailbox commands must always provide a nonzero `key_pair_id`.

Currently only LDevID (`key_pair_id = 1`) is a supported managed key anchor
point; FMC Alias (`2`) and RT Alias (`3`) are rejected as unsupported.

Integrators are responsible for validating certificate contents, required
extensions, and public-key binding to the selected key anchor point.

### Allocate managed endorsement storage

For each enabled managed slot (Owner and Tenant), the platform must allocate
persistent storage (such as dedicated flash partitions) and configure size limits:

- **Algorithm independence**: ECC P-384 and ML-DSA-87 must use disjoint,
  non-overlapping storage regions.
- **Role independence**: Owner and Tenant must use disjoint storage regions.
- **Sizing**: Allocate sufficient space for the configured maximum endorsement
  size plus storage metadata and double-buffering.
- **Persistence guarantees**: Storage must ensure atomic commits while keeping
  the active endorsement readable during updates, power-loss safety,
  deterministic recovery of the newest valid endorsement, and durable removal.

#### SDK reference implementation

The SDK provides a reference SPI-flash implementation (`SingleManagedEndorsement`
in `caliptra-mcu-cert-store`) that integrators can configure or replace to match
their platform storage:

- **Partition and A/B region layout**: On the emulator reference platform, the
  `512 KiB` certificate-store partition is divided into four disjoint `128 KiB`
  `(role, algorithm)` allocations (`Owner/Tenant` × `ECC P-384/ML-DSA-87`). Each
  allocation is split into two equal `64 KiB` A/B flash regions (`active_region`
  and `staging_region`, `MANAGED_REGION_COUNT = 2`).
- **Active-chain continuity**: Single-shot and multi-chunk `SET_CERTIFICATE`
  writes erase and program the `staging_region` while concurrent readers continue
  reading the `active_region` (`RegionReadGuard` prevents erasing a region while
  a reader is in flight).
- **Record metadata and recovery**: Each A/B region stores a DER endorsement
  chain preceded by an 80-byte `ManagedRecord` header (format version 2). The
  header identifies the chain and contains certificate metadata, integrity
  checks, and an update sequence number. Recovery verifies the header CRC and
  payload checksum, then selects the valid region with the highest sequence
  number. The DER payload is written and checksum-verified before the header is
  written and read-back verified.
- **Durable removal**: `erase` clears the older `staging_region` before the
  `active_region` so an interrupted erase cannot resurrect a superseded chain
  after reset. A failed erase recovers any surviving valid record before
  allowing another update. If recovery also fails, the slot remains
  unprovisioned and locked against updates until startup recovery after reset.

## Provide Vendor certificates

The Vendor slot is established during manufacturing and is strictly read-only:

- **Root and Intermediate CAs**: Embed the Vendor CA certificates in the
  application image.
- **IDevID certificates**: Supply the manufacturing-signed IDevID certificates
  for each enabled algorithm (e.g., from OTP or secure platform storage).
- Do not allocate writable persistent backing for the Vendor slot.

## Configure transport exposure

All enabled transports share the single initialized `CertStore` instance:

- **SPDM**: Uses `SpdmPalCertStore` to map negotiated algorithms and SlotIDs
  (default: Slot 0 Vendor, Slot 2 Owner, Slot 3 Tenant), advertising only
  available provisioned chains.
- **MCI mailbox**: Queries the store directly by algorithm and endorsement role
  (`Vendor`, `Owner`, `Tenant`). Command formats are defined in [External
  Mailbox Commands](./external_mailbox_cmds.md).

## Configure authorization

Vendor endorsements are read-only and cannot be modified.

For Owner and Tenant endorsements, platforms must enforce authorization before
passing updates to the certificate store:

- Validate requester identity and credentials.
- Verify permissions for the targeted slot, algorithm, and operation (write or erase).
- Ensure authorization requirements are consistent across all access transports.

## Initialize the certificate store

The application calls `cert_store::init(...)` once during startup:

1. Imports Vendor IDevID certificates and configures the Vendor slot.
2. Recovers persisted Owner and Tenant endorsements that match the provisioning policy.
3. Computes available certificate chains.
4. Shares the initialized store across SPDM and MCI responders.

Responder tasks (SPDM MCTP, SPDM DOE, MCI mailbox) must start only after
`cert_store::init(...)` succeeds. If initialization of the mandatory Vendor ECC
P-384 chain fails, startup must halt.

## Validate the integration

Verify the integrated certificate store:

1. **Chain retrieval**: Retrieve complete chains across all enabled transports
   (SPDM, MCI) and verify they match expectations from Root CA to DPE leaf.
2. **Attestation**: Verify attestation challenges against the retrieved leaf
   certificate.
3. **Availability**: Confirm that unprovisioned or failed chains are not
   advertised.
4. **Independent updates**: Verify that updating an Owner endorsement does not
   affect ML-DSA or Tenant chains.
5. **Atomic updates**: Verify that a failed or interrupted update leaves the
   previous valid endorsement intact.
6. **Cross-transport consistency**: Confirm that an update made via one transport
   is immediately visible on all other transports.
7. **Authorization enforcement**: Verify that unauthorized update attempts
   and writes to the Vendor slot are rejected without altering stored state.
