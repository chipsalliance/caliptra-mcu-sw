# Proposal: IDevID and Vendor Certificate Provisioning

This proposal provides context for the team discussion and identifies the
deployment models and provisioning controls that the MCU SDK could support.
It describes proposed behavior, not existing SDK capabilities.

## Background

IDevID and Vendor certificate provisioning has remained outside the MCU SDK's
scope. It has been treated as a manufacturing- and integrator-specific flow.
A growing number of integrators are now asking for vendor-neutral SDK commands.

The proposal is to provide common provisioning commands, while leaving storage
operations and platform security controls to the integrator.

## Deployment models

Combining the OOB certificate discussion in
[issue #2010](https://github.com/chipsalliance/caliptra-mcu-sw/issues/2010)
with other storage possibilities gives the following models for the
**Vendor certificate slot (SPDM Slot 0)**. Each model applies independently to
ECC P-384 and ML-DSA-87.

| No. | Option | Root / Intermediate CAs | IDevID certificate | Chain served by device | RootHash |
| --- | --- | --- | --- | --- | --- |
| 1 | Static CAs + OTP IDevID (SDK default) | MCU binary | OTP | RootCA -> .. -> IDevID -> LDevID -> .. -> DPE Leaf | SHA-384(RootCA) |
| 2 | Flash CAs + OTP IDevID | Platform flash | OTP | RootCA -> .. -> IDevID -> LDevID -> .. -> DPE Leaf | SHA-384(RootCA) |
| 3 | OOB CAs + OTP IDevID | Held out-of-band | OTP | IDevID -> LDevID -> .. -> DPE Leaf | SHA-384(IDevID) |
| 4 | All Vendor certificates OOB | Held out-of-band | Held out-of-band | LDevID -> .. -> DPE Leaf | SHA-384(LDevID) |
| 5 | All Vendor certificates in flash | Platform flash | Platform flash | RootCA -> .. -> IDevID -> LDevID -> .. -> DPE Leaf | SHA-384(RootCA) |

An OTP-backed IDevID may be a full DER certificate or a stored signature with
the required reconstruction template and attributes available. For OOB models
(Options 3 and 4), the verifier supplies the omitted certificates and validates
the complete path against its independently trusted Vendor Root CA. **RootHash
identifies the first certificate served; it does not establish trust.**

## Security considerations

Private keys remain inside Caliptra regardless of where certificates are stored.
For a correctly configured verifier, certificate substitution alone does not
enable device impersonation:

<pre>
<b>Genuine chain:</b>
  <span style="color:#2da44e">[Trusted Vendor Root CA] ---&gt; [IDevID (Device_A_pub)] ---&gt; [LDevID (signed by Device_A_priv)] ---&gt; [FMC -&gt; RT -&gt; Leaf]</span>

<b>1. Fake IDevID public key:</b>
  <span style="color:#2da44e">[Trusted Vendor Root CA]</span> <span style="color:#cf222e">-✗-&gt; [Fake IDevID (Attacker_pub)] -✗-&gt;</span> <span style="color:#2da44e">[LDevID (signed by Device_A_priv)] ---&gt; [FMC -&gt; RT -&gt; Leaf]</span>

<b>2. Rogue CA endorsing the real IDevID public key:</b>
  <span style="color:#2da44e">[Trusted Vendor Root CA]</span> <span style="color:#cf222e">-✗-&gt; [Rogue CA ---&gt; IDevID (Device_A_pub)]</span> <span style="color:#2da44e">---&gt; [LDevID (signed by Device_A_priv)] ---&gt; [FMC -&gt; RT -&gt; Leaf]</span>

<b>3. Another genuine device's IDevID certificate:</b>
  <span style="color:#2da44e">[Trusted Vendor Root CA] ---&gt;</span> <span style="color:#cf222e">[IDevID (Device_B_pub)] -✗-&gt;</span> <span style="color:#2da44e">[LDevID (signed by Device_A_priv)] ---&gt; [FMC -&gt; RT -&gt; Leaf]</span>
</pre>

Provisioning still requires local access control because bad writes can denial-of-service the device:

| Storage | Main risks |
| --- | --- |
| OTP | Incorrect or malicious programming permanently invalidates the Vendor endorsement and bricks the device. |
| Flash | Unauthorized overwrite or erasure breaks attestation, requiring offline RMA recovery or Owner-authorized in-field re-provisioning. |

## Authorization model

- **Manufacturing:**
  - If the device is in **Manufacturing** lifecycle mode, no command
    authorization is required.
  - If manufacturing runs in **Prod** lifecycle mode, the vendor either uses a
    custom manufacturing MCU image that bypasses authorization (followed by a
    production MCU update with an incremented SVN for anti-rollback before
    shipping) or signs with an installed authorization key.
- **In-field (Prod):**
  - **Option 4 (All OOB):** No on-device Vendor storage; no authorization needed.
  - **OTP `IDevID` (Options 1, 2, 3):** Burned once and hardware-locked during
    manufacturing; permanently immutable in the field.
  - **Flash Vendor certificates (Options 2 and 5):** Because flash is rewritable
    in the field, writes always fail closed and require `0x12` cryptographic
    authorization under an installed Vendor or Owner authorization key.

| Operation | Applicable options | Authorization requirement | SDK / platform behavior |
| --- | --- | --- | --- |
| OTP `IDevID` write (`MC_PROVISION_IDEV_CERT`) | Options 1, 2, 3 | None in manufacturing (unlocked OTP partition only) | Rejects if partition is locked (`InvalidState`). Supports `StageAndPopulate` (pre-burn chain check via `GET_CERTIFICATE` / `MC_GET_CERT_CHAIN`) or `WriteOtp` (burn + read-back verify + lock). |
| Flash Vendor write (Options 1A or 1B below) | Options 2, 5 | Required in Prod (Vendor or Owner authorization key, unless bypassed in a mfg build with SVN bump) | Fails closed (`AccessDenied`) if neither key is installed; stages in the inactive A/B flash region and flips `active_region` only on verified write. |

## Proposed command set and flow

For Flash Vendor certificates (Options 2 and 5), we have two command design
options using the same A/B flash region mechanism:

- **Option 1A (Dedicated Vendor commands):** Keeps `SET_CERTIFICATE` and
  `MC_SET_CERT_CHAIN` scoped strictly to Owner and Tenant. `0x12` authorizes
  `MC_AUTH_PROVISION_VENDOR_CERT(algo, total_size, expected_sha384)` to arm Slot
  0, and `MC_PROVISION_VENDOR_CERT` streams the chunks and verifies `SHA-384`.
- **Option 1B (Reuse `SET_CERTIFICATE` / `MC_SET_CERT_CHAIN` under `0x12`):**
  Reuses `SET_CERTIFICATE` (`slot_id = 0`) and `MC_SET_CERT_CHAIN` (`role = 0`)
  directly inside `0x12` with the trailing `AuthorizationBlock`
  (`[target_id | payload | AuthorizationBlock]`), delivered via `CHUNK_SEND`
  over SPDM.

For OTP `IDevID` provisioning (Options 1, 2, and 3), `MC_PROVISION_IDEV_CERT`
accepts a `mode` option backed by a platform trait (`StageAndPopulate` for
pre-burn verification or `WriteOtp` to burn and lock OTP):

<pre>
<b>1A. Flash Vendor certificates — Dedicated Vendor commands (Options 2 and 5):</b>

  MC_AUTHORIZED_COMMAND (0x12)
  └── MC_AUTH_PROVISION_VENDOR_CERT(algo, total_size, expected_sha384)
        │  1. Verifies Vendor/Owner signature and arms Slot 0 (algo) in cert-store
        ▼
  MC_PROVISION_VENDOR_CERT(algo, offset, total_size, data)
        │  2. Checks armed state; streams chunks into inactive A/B flash region
        │  3. Final chunk: verifies SHA-384 == expected_sha384
        ├──► <span style="color:#2da44e">Match:    flips active_region and bumps generation_counter</span>
        └──► <span style="color:#cf222e">Mismatch: discards staging_region; active_region unchanged</span>

<b>1B. Flash Vendor certificates — Reuse SET_CERTIFICATE / MC_SET_CERT_CHAIN under 0x12 (Options 2 and 5):</b>

  AUTHORIZED_COMMAND / MC_AUTHORIZED_COMMAND (0x12, streamed via CHUNK_SEND on SPDM)
  └── [ target_id = SET_CERTIFICATE / MC_SET_CERT_CHAIN (slot/role = 0)
      | certificate chain payload
      | AuthorizationBlock trailer (nonce || pubkeys || HybridSignature) ]
        │  1. Streams cert payload into Slot 0 inactive A/B flash region + incremental SHA-384/512
        │  2. Verifies Vendor/Owner hybrid signature in trailing AuthorizationBlock
        ├──► <span style="color:#2da44e">Valid signature:   flips active_region and bumps generation_counter</span>
        └──► <span style="color:#cf222e">Invalid signature: discards staging_region; active_region unchanged</span>

<b>2. Manufacturing OTP IDevID provisioning (Options 1, 2, and 3 — unauthenticated):</b>

  MC_PROVISION_IDEV_CERT(algo, mode, offset, total_size, data)
        │  1. Rejects (InvalidState) if IDevID OTP partition is already locked
        │  2. Streams IDevID cert or signature into platform handler
        ├──► <span style="color:#0969da">mode = StageAndPopulate: reconstructs/stages cert -&gt; POPULATE_IDEV_*_CERT</span>
        │      <span style="color:#0969da">(host can read &amp; verify full chain via GET_CERTIFICATE / MC_GET_CERT_CHAIN)</span>
        └──► <span style="color:#2da44e">mode = WriteOtp:         burns &amp; verifies OTP -&gt; locks OTP partition -&gt; POPULATE_IDEV_*_CERT</span>
</pre>

| Option | OTP command (`MC_PROVISION_IDEV_CERT`) | Flash command (Option 1A or Option 1B) |
| --- | --- | --- |
| 1. Static CAs + OTP IDevID | Provisions `IDevID` (cert or signature) into OTP | Not used (CAs compiled into MCU) |
| 2. Flash CAs + OTP IDevID | Provisions `IDevID` (cert or signature) into OTP | Provisions `RootCA -> .. -> IntCA` into Flash Slot 0 |
| 3. OOB CAs + OTP IDevID | Provisions `IDevID` (cert or signature) into OTP | Not used (CAs held OOB) |
| 4. All Vendor certs OOB | Not used | Not used |
| 5. All Vendor certs in Flash | Not used (`IDevID` is in Flash) | Provisions `RootCA -> .. -> IDevID` into Flash Slot 0 |

## SDK and integrator responsibilities

| Responsibility | Owner |
| --- | --- |
| Define `MC_PROVISION_IDEV_CERT` and the selected Flash Slot 0 command path (Option 1A or 1B), and enforce the authorization and OTP-lock rules above | SDK |
| Stage Flash Slot 0 writes in the inactive A/B region and flip `active_region` only after digest/signature verification | SDK |
| Implement platform-specific `IDevID` staging/reconstruction, `POPULATE_IDEV_*_CERT` invocation, OTP burn + read-back verification, and OTP partition locking | Integrator |
| Choose the deployment model (Options 1–5) | Integrator |
| Provision and lock the `IDevID` OTP partition during manufacturing (and advance SVN if transitioning from a custom manufacturing image) before shipping | Integrator |
| Securely install Vendor and Owner authorization keys and policies, and supply OTP/flash storage implementations | Integrator |

## Decisions for discussion

1. Which of the five Vendor deployment models should the SDK support?
2. For Flash Slot 0 (Options 2 and 5), should we use dedicated Vendor commands (Option 1A: `MC_AUTH_PROVISION_VENDOR_CERT` + `MC_PROVISION_VENDOR_CERT`) or reuse `SET_CERTIFICATE` / `MC_SET_CERT_CHAIN` under `0x12` (Option 1B)?
3. Does `MC_PROVISION_IDEV_CERT` (`StageAndPopulate` / `WriteOtp`) with the hardware OTP partition lock meet integrator manufacturing requirements?
