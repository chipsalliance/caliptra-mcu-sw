# Caliptra Authorization Model - Brainstorm

---

## 1. Assets, lifecycle, and responsible party

The responsible parties for the first eight rows come from
[`caliptra-mcu-sw#1871`, comment 5121487348](https://github.com/chipsalliance/caliptra-mcu-sw/issues/1871#issuecomment-5121487348).
Additional rows come from current commands, certificate-slot documentation,
and firmware-update documentation.

**Assumption:** Command authorization is not required in Manufacturing mode;
this model applies authorization to in-field operations.

| Asset/operation | Lifecycle | Responsible party |
| --- | --- | --- |
| Vendor PK hashes | Manufacturing and in-field | Vendor |
| Vendor PK hash revocation | In-field | Vendor or Owner |
| Vendor key revocation | In-field | Vendor or Owner |
| Anti-rollback fuses | In-field | Owner |
| Field entropy | In-field | Owner |
| LOCK HEK rotation | TBD | Owner |
| LOCK Perma HEK fuse | TBD | Owner |
| DOT | In-field; initial enablement platform dependent | Owner |
| Owner PK hash provisioning | Owner onboarding/in-field | Owner |
| Generic in-field fuse read/write/lock | In-field | Vendor or Owner, depending on the selected fuse; current generic commands do not enforce this distinction |
| Vendor certificate endorsement, slot `0` | Manufacturing | Vendor |
| Owner certificate endorsement, slot `2` | In-field | Owner |
| Tenant certificate endorsement, slot `3` | In-field | TBD; no authorization mechanism or responsible party defined |
| Firmware update initiation/activation | In-field | TBD |

---

## 2. Current command-authorization format

There are no separate Vendor and Owner command-authority key slots today. The
test implementation embeds one 48-byte SHA-384 hash anchor over one combined
ECDSA P-384 and ML-DSA-87 command-authority public-key set. Every authorized
request carries the command-specific payload first, followed by this
authorization trailer:

```text
command-specific payload || authorization trailer
```

**Current authorization trailer**

| Trailer field | Size |
| --- | ---: |
| Challenge nonce | 48 bytes |
| ECDSA P-384 public key X coordinate | 48 bytes |
| ECDSA P-384 public key Y coordinate | 48 bytes |
| ML-DSA-87 public key | 2592 bytes |
| ECDSA P-384 signature R | 48 bytes |
| ECDSA P-384 signature S | 48 bytes |
| ML-DSA-87 signature | 4628 bytes |

Both signatures bind the command ID, command-specific payload, and challenge
nonce.

MCU Runtime hashes the received public keys and compares the result with the
embedded test anchor before verifying both signatures. It has no production
method to provision, select, update, or separately enforce Vendor and Owner
command-authority key sets.

---

## 3. Proposed Caliptra users and credential + policy provisioning

The proposed model has two command-authorization users:

| User | Command-authority credential | Command policy |
| --- | --- | --- |
| Vendor | One ECDSA P-384 public key and one ML-DSA-87 public key | Vendor policy, format TBD |
| Owner | One ECDSA P-384 public key and one ML-DSA-87 public key | Owner policy, format TBD |

### Commonly agreed provisioning proposal

[`Caliptra#729`](https://github.com/chipsalliance/Caliptra/issues/729)
defines separate fixed Vendor and Owner IMEs that endorse separate command-key
sets.

| User | Fixed IME ID | Manifest source | Proposed IME content |
| --- | --- | --- | --- |
| Vendor | `VENDOR_COMMAND_AUTH_KEY_ID` | Original vendor-authorized SoC manifest | One digest over the Vendor key set and policy |
| Owner | `OWNER_COMMAND_AUTH_KEY_ID` | Owner-only authorized SoC manifest | One digest over the Owner key set and policy |

- The IME contains one combined key-set-and-policy digest, not the public keys
  or policy contents; its encoding is TBD.
- MCU-side command(s) for installing Vendor and Owner credentials and policies
  are to be defined. The provisional `MC_INSTALL_COMMAND_AUTH_KEYS` covers keys
  only and must be extended or paired with a policy-installation command.
- After Caliptra authorizes the combined digest, MCU Runtime installs the credential
  and policy for the corresponding authority.

---

## 4. Proposed Caliptra authorization flow

| Phase | Proposed flow |
| --- | --- |
| Endorse credential and policy | Fixed Vendor and Owner IMEs in their respective authorized SoC manifests bind one combined key-set-and-policy digest |
| Install credential and policy | New MCU command(s) supply the authority, public keys, and policy; Caliptra validates the combined digest against the fixed IME; MCU Runtime installs them for that authority |
| Authorize request | Requester gets a one-time challenge, signs the command, authority, and challenge with both keys, and appends the authorization trailer |
| Verify and execute | MCU Runtime checks the installed policy, consumes the challenge, verifies both signatures with the selected credential, and executes only on success |

```text
authorization trailer =
    authority || challenge || ECDSA P-384 signature || ML-DSA-87 signature
```

---

## 5. Caliptra commands using authorization

Current code does not distinguish Vendor and Owner authorization. **MCI mailbox
and SPDM VDM use the same test authorization mechanism.**

| Device operation/command | MCI mailbox | SPDM VDM |
| --- | :---: | :---: |
| `MC_PROVISION_VENDOR_PK_HASH` | Yes | Yes |
| `MC_PROVISION_OWNER_PK_HASH` | Yes | Yes |
| `MC_FUSE_INCREASE_CALIPTRA_MIN_SVN` | Yes | Yes |
| `MC_FE_PROG` | Yes | Yes |
| `MC_FUSE_REVOKE_VENDOR_PUB_KEY` | Yes | Yes |
| `MC_FUSE_REVOKE_VENDOR_PK_HASH` | Yes | Yes |
| `MC_FUSE_READ`, `MC_FUSE_WRITE`, `MC_FUSE_LOCK_PARTITION` | Yes | Lock only |
| `DotLock`, `DotDisable`, `DotRotate`, `GetDotBackupBlob` | Yes | Yes |

The current raw fuse-write path accepts a word address and has no software
address allowlist.

**Proposed extension:** Extend command authorization to PLDM firmware updates
and certificate provisioning for managed slots.

---

## 6. DSP0289 messages and their fit

| DSP0289 category | Message(s) | Requirement | Purpose and fit |
| --- | --- | --- | --- |
| Discovery | `GET_AUTH_VERSION`, `SELECT_AUTH_VERSION`, `GET_AUTH_CAPABILITIES` | Mandatory | Discover and select the Authorization version and capabilities before slides 4 and 5 |
| Credential and policy provisioning | `SET_CRED_ID_PARAMS`, `SET_AUTH_POLICY` | Optional | Provision, change, lock, or unlock credentials and policies; DSP0289 alternative to slide 4 installation |
| Credential and policy query | `GET_CRED_ID_PARAMS`, `GET_AUTH_POLICY` | Mandatory | Report the credential and policy installed by the slide 4 flow |
| USAP session management | `START_AUTH`, `END_AUTH` | Optional; required when USAP is supported | Start and end the User-specific authorization session carrying slide 5 commands |
| Ownership and reset | `TAKE_OWNERSHIP`, `AUTH_RESET_TO_DEFAULT` | `TAKE_OWNERSHIP` mandatory; reset optional | Transition once from `DefaultState` to `Owned`, or reset unlocked state to defaults |
| Process and error management | `GET_AUTH_PROCESSES`, `KILL_AUTH_PROCESS`, `AUTH_ERROR` response | Process commands optional; `AUTH_ERROR` mandatory | List or terminate Authorization processes and report failures |

**Slide 5 Caliptra commands are not DSP0289 request codes.** During USAP, each
Caliptra command and payload is carried as the message requiring authorization
inside an Authorization Record.

---

## 7. Authorization process options

| Profile | Process |
| --- | --- |
| Caliptra proposal | Fixed Vendor/Owner IME -> MCU credential/policy installation -> challenge -> Caliptra command with authorization trailer -> verify and execute |
| Hybrid under assessment | Fixed Vendor/Owner IME -> MCU credential/policy installation -> DSP0289 discovery and query -> `START_AUTH` -> Authorization Record carrying a Caliptra command -> `END_AUTH` |
| Full DSP0289 | DSP0289 discovery -> `SET_CRED_ID_PARAMS` and `SET_AUTH_POLICY` -> query and verify -> `START_AUTH` -> Authorization Record carrying a Caliptra command -> `END_AUTH` |

The hybrid profile uses Caliptra provisioning from slide 4 and DSP0289 USAP
for the slide 5 commands. MCI mailbox and SPDM VDM use the same Authorization
messages, Records, Credential IDs, policies, and authorization core, with
transport-specific bindings and separate session state.

Pre-provisioning the credential and policy does not set the DSP0289 state to
`Owned`. `TAKE_OWNERSHIP` is performed once during onboarding while the target
is in `DefaultState`:

```text
START_AUTH -> authorized TAKE_OWNERSHIP -> END_AUTH
```

The resulting ownership state is persisted. If ownership was already taken
before deployment, this flow is not repeated during normal operation.

**Multi-command difference:** The Caliptra proposal repeats challenge request
-> signed command for every command. USAP performs `START_AUTH` once, carries
multiple signed Authorization Records using the session nonces and implicit
sequence, and then performs `END_AUTH`.

---

## 8. Option comparison

| Evaluation criterion | Caliptra proposal | Manifest bootstrap + DSP0289 USAP | Full DSP0289 |
| --- | --- | --- | --- |
| Fixed Vendor and Owner trust from signed manifests | Meets | Meets | Requires a separate initial provisioning profile |
| ECDSA P-384 + ML-DSA-87 hybrid authorization | Meets | DSP0289 gap | DSP0289 gap |
| One authorization protocol for MCI and SPDM | Meets with a Caliptra-specific protocol | Meets after defining the MCI binding | Meets after defining the MCI binding |
| Multiple commands in one authorization session | Does not meet; challenge required per command | Meets | Meets |
| Avoid DSP0289 setter commands and mutable credential database | Meets | Meets | Does not meet |
| Dynamic users and Credential IDs, such as Tenant | Does not meet | Does not meet | Meets |
| Standards and system interoperability | Does not meet | DSP0289 authorization; Caliptra-specific provisioning | Strongest |
| Authorization-key rotation requires | Update the corresponding signed manifest IME and reinstall the key set | Update the corresponding signed manifest IME and reinstall the key set | Issue an authorized `SET_CRED_ID_PARAMS`; use `SET_AUTH_POLICY` only if the policy also changes |
| Relative implementation scope | Lowest | Medium | Highest |

---

## 9. DSP0289 gaps

Use DSP0289 as the baseline and address these gaps through DMTF:

1. Add ML-DSA-87 and hybrid ECDSA P-384 + ML-DSA-87 support.
2. Define how the same Authorization messages and Records are carried over
   different transports, including MCI mailbox.
