# Caliptra Authorization Credential Provisioning

## References

- [DSP0289 1.0, section 8.6, Initial provisioning](https://www.dmtf.org/sites/default/files/standards/documents/DSP0289_1.0.0.pdf#page=30)
- [caliptra-mcu-sw PR #906, WIP: SPDM authorization with hybrid OTP+Flash storage](https://github.com/chipsalliance/caliptra-mcu-sw/pull/906)

PR #906 assigns the Credential IDs as follows:

| Credential ID | Role |
| ---: | --- |
| `0` | Recovery |
| `1` | Vendor |
| `2` | Owner |
| `3` | Tenant |

## Lifecycle overview

```text
Manufacturing
    |
    v
DefaultState: Vendor provisioning
    |
    v
DefaultState: Owner onboarding
    |
    +-- Optional: provision Tenant ID 3 before ownership
    |
    v
TAKE_OWNERSHIP
    |
    v
Owned: authorization fully enforced
    |
    +-- Optional: provision Tenant ID 3 through an authorized flow
```

## Key concepts

- A credential identifies an authority; its policy defines what that
  authority may do.
- `SET_AUTH_POLICY` and `SET_CRED_ID_PARAMS` provision the policy and
  credential. The target persists them in `CRED_BLOB`.
- HMAC and the anti-rollback counter protect `CRED_BLOB`. Locking separately
  prevents one Credential ID and its policy from being changed.
- `TAKE_OWNERSHIP` changes the whole device from `DefaultState` to `Owned` and
  enables authorization enforcement. Before ownership, only provisioning for
  unlocked Credential IDs bypasses authorization; other protected operations
  remain denied.

## Detailed lifecycle

### 1. Manufacturing establishes recovery

- Vendor provisions the Credential ID `0` public-key digest into OTP.
- Firmware supplies the full public key, fixed attributes, and recovery policy.
- Credential ID `0` is locked.
- Device enters DSP0289 `DefaultState`; IDs `1`-`3` are unprovisioned.

**Open question:** After Recovery Credential ID `0` is provisioned and the
device enters Production without any operational credentials, how should
Caliptra represent `DefaultState` when `CRED_BLOB` does not exist?

### 2. Vendor establishes supply-chain authority

- In a Vendor-controlled facility, Vendor provisions and verifies the
  credential and policy for Credential ID `1`.
- The target persists the Vendor credential and policy in `CRED_BLOB`;
  Recovery Credential ID `0` remains outside the blob.
- Vendor authenticates using Credential ID `1` and locks the credential and
  its policy.
- Device remains in `DefaultState`.

**Gaps:**

- PR #906 currently defines Credential ID `1` as non-lockable.
- Vendor policy and permitted Production operations are not fully defined.

### 3. Vendor-to-Owner custody transfer

- Device leaves Vendor custody with:
  - Recovery Credential ID `0` locked.
  - Vendor Credential ID `1` locked.
  - Owner Credential ID `2` unprovisioned.
  - Tenant Credential ID `3` unprovisioned.
- Device remains in `DefaultState`.

**Open question:** How is access to initial credential-provisioning commands
controlled during shipment and custody transfer?

### 4. Owner onboarding establishes device administration

- In an Owner-controlled environment, Owner verifies Vendor Credential ID `1`
  and its policy.
- Owner provisions:
  - Owner policy for Credential ID `2`.
  - Owner credential ID `2`.
- The Owner policy determines whether Credential ID `2` may administer other
  Credential IDs.
- Owner authenticates using Credential ID `2` and locks the credential and
  policy.
- Owner verifies all provisioned credentials and policies.

**Gap:** PR #906 currently defines Credential ID `2` as non-lockable. The
Owner policy and its administrative privileges are not fully defined.

### 5. Tenant authority is established

Tenant Credential ID `3` could be provisioned:

- Before ownership as part of Owner onboarding.
- After ownership through an authorized provisioning flow.

**Open questions:**

- Who supplies and provisions the Tenant credential and policy?
- If provisioning occurs after ownership, which credential authorizes it?

### 6. Owner takes ownership

- Owner authenticates using Credential ID `2`.
- Owner sends `TAKE_OWNERSHIP`.
- Device transitions from `DefaultState` to `Owned`.
- Authorization policies are enforced for protected operations and future
  credential or policy changes.
- Per-Credential-ID lock states remain unchanged.

**Open questions:**

- How is `Owned` persisted?
- What operation does `TAKE_OWNERSHIP` perform on `CRED_BLOB`, if any?

### 7. Normal Production operation

- Vendor uses Credential ID `1`.
- Owner uses Credential ID `2`.
- Tenant uses Credential ID `3`, if provisioned.
- Each credential can perform only operations allowed by its policy.

**Open question:** What is the complete operation-to-role policy for Vendor,
Owner, and Tenant?

### 8. Recovery returns the device to provisioning

- If operational credentials are lost or corrupt, the device exposes Recovery
  Credential ID `0`.
- Recovery authority authenticates `AUTH_RESET_TO_DEFAULT`.
- PR #906 wipes `CRED_BLOB` and returns the device to `DefaultState`.
- Operational credentials and policies are provisioned again.
- Owner calls `TAKE_OWNERSHIP` again.

**Gap:** The proposed sequence locks Vendor and Owner credentials, while PR
#906 defines IDs `1`-`3` as non-lockable and wipes their blob during reset.
DSP0289 requires locked credentials and policies to survive
`AUTH_RESET_TO_DEFAULT`.

## State summary

- **`Unprovisioned` to `DefaultState`:** Vendor provisions and locks Recovery
  Credential ID `0`. Operational Credential IDs `1`-`3` remain unprovisioned.
- **While in `DefaultState`:** Vendor ID `1`, Owner ID `2`, and optionally
  Tenant ID `3` are provisioned. Provisioning or locking an individual
  Credential ID does not change the device-wide state.
- **`DefaultState` to `Owned`:** Owner authenticates using Credential ID `2`
  and successfully calls `TAKE_OWNERSHIP`.
- **While `Owned`:** Authorization is enforced for protected operations.
  Tenant ID `3` may be provisioned through an authorized flow. Existing
  per-Credential-ID lock states remain unchanged.
- **`Owned` to `DefaultState`:** Recovery authority authenticates using
  Credential ID `0` and successfully calls `AUTH_RESET_TO_DEFAULT`.

## Provisioning model comparison

| Aspect | Manifest-based provisioning | DSP0289 setters with `CRED_BLOB` |
| --- | --- | --- |
| Credential trust source | A role-specific signed manifest entry endorses the Credential ID, public-key set, and policy digest or version. | A provisioning actor supplies the credential and policy through `SET_CRED_ID_PARAMS` and `SET_AUTH_POLICY`. |
| Initial trust boundary | The target accepts only values matching the authenticated Vendor or Owner manifest. | The target trusts the environment and transport allowed to use the unlocked setters in `DefaultState`. |
| Persistent source | The signed manifest is the durable trust source. Credentials can be activated in protected volatile storage and revalidated at each boot. | Credentials and policies are persisted in a mutable flash `CRED_BLOB`. |
| Flash protection | Manifest signatures, authenticated digests, and manifest version enforcement protect the credential binding. A cached credential can be treated as untrusted and revalidated. | A device-derived HMAC protects the blob from direct modification, and `CRED_FUSE_ARRAY` is proposed to prevent rollback. |
| What protection proves | The credential and policy were endorsed by the authority that signed the manifest. | The blob was produced by the target and has not been modified or rolled back after it was stored. |
| Credential changes | Replace the applicable signed manifest and reactivate the credential. | Use an authorized setter, update the blob, compute a new HMAC, and advance the anti-rollback counter. |
| Locking | Manifest-backed credentials are effectively fixed if setters are unsupported; changing them requires a new authorized manifest. | Each supported Credential ID can be locked independently. Unlocked credentials remain mutable according to the current device state and policy. |
| Tenant and delegated credentials | Requires an Owner-signed Tenant manifest entry or another manifest extension. | Supports dynamic Tenant and delegated credential provisioning through the DSP0289 setter flow. |
| Power-failure handling | Relies on the authenticated manifest-update and activation mechanism. Invalid cached data can be rejected and reinstalled from the manifest. | Requires an atomic `CRED_BLOB` and fuse-counter update sequence, such as an A/B blob scheme. |
| Recovery | Reinstall or reactivate the credential from the current authenticated manifest. | Recovery Credential ID `0` authorizes `AUTH_RESET_TO_DEFAULT`, followed by operational credential reprovisioning. |
| `TAKE_OWNERSHIP` | Still requires a protected persistent representation of `DefaultState` versus `Owned`. | Still requires a protected persistent representation of `DefaultState` versus `Owned`; the proposed blob does not currently include it. |

Manifest-based provisioning can replace the mutable `CRED_BLOB` for fixed
Vendor and Owner credentials if the manifest binding includes the Credential
ID, key set, and policy. The current RFC 729 proposal must be extended to bind
the policy and reconciled with PR #906's Credential ID allocation.

If Tenant credentials or manifest-independent credential rotation are
required, the profile can either extend the Owner manifest or retain a
protected mutable store for those credentials. The authority for and
persistence of the device-wide ownership state must be defined independently
in either model.
