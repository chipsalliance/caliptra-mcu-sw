# Command Auth Key Management

**Status:** Discussion note

## Context

MCU Runtime needs trusted key material to authorize security-sensitive
commands. The command authorization key set contains two asymmetric public
keys: ECDSA P-384 and ML-DSA-87. Every authorized command must carry signatures
from both corresponding private keys, and MCU Runtime must verify both
signatures before executing the command.

## Option 1: Embed Keys in MCU Runtime

Compile both command authorization public keys into the MCU Runtime image. The
authenticated MCU Runtime image establishes trust in the embedded key set.

- **Pro:** No key-installation command or mutable key store is needed.
- **Con:** Rotating or revoking either key requires a new MCU Runtime image and
  a new SoC manifest containing its digest. This usually requires a new vendor
  signature unless the vendor has relinquished IME signature validation.

## Option 2: Authorize a Key Digest Through an Owner IME

Add the digest of the command authorization key set as a dedicated Image
Metadata Entry (IME) in an owner-only SoC manifest. The digest covers a
canonical encoding of both the ECDSA P-384 and ML-DSA-87 public keys. Define an
MCU Runtime command that installs both public keys atomically. MCU Runtime
hashes the supplied key set and asks Caliptra Runtime to authorize the digest
against the active owner IME before accepting it. To rotate either key, install
a new owner-only SoC manifest containing the replacement key-set digest, then
install both matching public keys.

- **Pro:** Rotation or revocation requires a new owner-only SoC manifest and
  matching key-set installation, but no new vendor signature or MCU Runtime
  image.
- **Con:** This requires an installation command and protected storage for both
  public keys. The installed key set's authorization must remain bound to the
  active owner-only SoC manifest.

## Option 3: Use SPDM Authorization

Use the [SPDM Authorization Specification
(DSP0289)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0289_1.0.0.pdf)
as the command authorization framework. Provision owner or administrator
credentials and associate them with a Caliptra-specific policy that grants
access to selected MCU commands.

The User-Specific Authorization Process (USAP) is the closest fit for an
external command signer. The signer establishes an SPDM secured session, starts
USAP, and wraps the complete Caliptra command message in a DSP0289 Authorization
record using the DSP0289 SPDM VDM binding. The existing Caliptra
`AuthorizedCommand` payload can be the protected inner message. The USAP
signature covers the Credential ID, both session nonces, a sequence number, and
the complete command body. MCU Runtime verifies the authorization record and
policy before dispatching the command.

DSP0289 version 1.0 does not natively represent the required hybrid key set. A
Credential ID selects one asymmetric algorithm, and the specification defines
ECDSA P-384 but not ML-DSA-87. This option therefore requires either a future
DSP0289 revision or a Caliptra-specific extension that binds the ECDSA P-384
and ML-DSA-87 public keys into one atomic credential and requires both
signatures over the same authorization transcript. Until that extension is
defined, DSP0289 can provide session and policy authorization while the inner
Caliptra `AuthorizedCommand` retains its existing hybrid signature.

An authorized credential update can rotate the key set without a new SoC
manifest or MCU Runtime image. Both public keys must be replaced atomically.
DSP0289 requires replacement credentials to take effect immediately and
terminates authorization processes that used the previous credential.

- **Pro:** Standardizes credential and policy management, command signatures,
  session binding, freshness, replay protection, and credential rotation.
- **Con:** Requires DSP0289 message handling, a hybrid-credential extension,
  integrity-protected credential and policy storage, a Caliptra-specific
  command privilege policy, and SPDM secured-session integration. It applies
  natively to SPDM-carried commands; direct MCI mailbox commands require a
  trusted proxy that preserves the verified authorization context.

DSP0289 does not by itself establish the initial owner. Its default state allows
unlocked Credential IDs to be provisioned before `TAKE_OWNERSHIP` and assumes
that this occurs in a trusted environment. To avoid a first-claim race, the
initial credential must be authorized by an existing trust anchor, such as the
owner IME in Option 2, or provisioned through a controlled platform flow.

USAP is preferable to the SPDM Endpoint Authorization Process (SEAP) for the
initial implementation. SEAP requires requester mutual authentication, which
the current SPDM responder does not support.

## Comparison

| | Embedded keys | Owner-IME-authorized keys | DSP0289 Authorization |
| --- | --- | --- | --- |
| Key material | ECDSA P-384 + ML-DSA-87 public keys | Digest-authorized ECDSA P-384 + ML-DSA-87 public keys | Hybrid credential extension required for ECDSA P-384 + ML-DSA-87 |
| Signature requirement | Both signatures | Both signatures | Both signatures through an extension or the inner `AuthorizedCommand` |
| Implementation | Simpler | Custom atomic key-set installation and manifest authorization | Credentials, policies, authorization sessions, and hybrid extension |
| Initial trust anchor | Authenticated MCU Runtime | Owner-only SoC manifest | Pre-provisioned or owner-IME-authorized credential |
| Rotation artifact | New MCU Runtime and SoC manifest | New owner-only SoC manifest | Authorized credential update |
| New vendor signature for key rotation | Usually yes; no if the vendor has relinquished IME signature validation | No | No |
| New MCU Runtime for rotation | Yes | No | No |
| Replay protection | Custom | Custom | Defined by USAP |