# Attestation Architecture

This document describes the attestation architecture for devices that integrate the Caliptra Subsystem, including Caliptra Core and MCU Runtime, to provide attesting environments for platform and SoC inventory attestation.

The architecture shows how Caliptra Core and MCU Runtime build and maintain the DICE/DPE trust chain, how downstream SoC measurements are collected, and how the DICE/DPE certificate chain and OCP EAT claims together describe comprehensive device state.

## Scope

This document addresses:

1. DPE context tree topology and attestation key target selection.
2. TCB and non-TCB claim classification.
3. How the DICE/DPE certificate chain and OCP EAT claims together let a Verifier appraise device identity and inventory claims.
4. How MCU Runtime assembles inventory Evidence for platform and SoC components.
5. Confidential-compute attestation is out of scope for this document and will be covered separately.

Detailed DPE command semantics, handle lifecycle mechanics, Caliptra ROM boot internals, and SPDM transport binding are covered by their corresponding design documents and specifications.

## Terminology

| Term | Definition |
| --- | --- |
| TCB Component | Firmware or hardware whose integrity directly affects the device security posture. In this architecture, integrator-selected SoC TCB components are represented as DPE contexts. TCB components on the selected attestation-key path are represented in the DICE/DPE certificate chain and are not repeated as OCP EAT inventory claims. TCB components outside that path are reported as OCP EAT inventory claims. |
| Non-TCB Component | Firmware or hardware whose claims are collected by MCU Runtime but do not participate in CDI or attestation key derivation. These claims are managed in Software PCR Storage backed by access-protected MCU SRAM and included directly as OCP EAT inventory claims. |
| DPE Context Tree | Directed tree of DPE contexts maintained by the Caliptra DPE instance. The tree mirrors the layered DICE trust chain. |
| AK | Attestation key derived by DPE through `CertifyKey` at a selected DPE context. |
| AK Target Node | Configured DPE context used for `CertifyKey`. It determines which DPE ancestry contributes to the attestation key. |
| Configured SoC Component | SoC component whose `fw_id` is explicitly listed in the integrator static attestation configuration. Only configured components are routed to DPE-backed TCI state or Software PCR Storage and emitted as inventory Evidence according to that policy. |
| Evidence | RATS conceptual message created by an Attester and conveyed to a Verifier. In this architecture, Evidence includes the DICE/DPE certificate chain and OCP EAT claims that describe device identity and inventory claims. |
| OCP EAT Claims | OCP EAT profile-compliant claims assembled by MCU Runtime. MCU Runtime owns the OCP EAT and COSE formatting and asks Caliptra Core to sign the result using the configured AK. |
| Backdoor Update | DPE context update performed by Caliptra RT through internal state update mechanisms, without externally visible DPE handles. Used for Caliptra-managed contexts such as Root, CCIV, and MCU Runtime. |

## Device composition model

A device built on the Caliptra Subsystem contains:

1. **Caliptra Core**: Hardware root of trust containing ROM, FMC, and Runtime firmware. Caliptra Runtime hosts the DPE engine, services DPE requests from MCU Runtime, protects DPE state and attestation key material, and signs data provided by MCU Runtime using the configured AK.
2. **MCU Runtime**: Privileged DPE client, acting as a PL0 user, that Caliptra Core measures and authorizes before MCU Runtime is trusted to attest downstream SoC components. MCU Runtime holds its own DPE context handle and DPE context handles for integrator-selected SoC TCB components. It measures and authorizes SoC components, manages protected measurement state, assembles OCP EAT claims, and owns the evidence format signed by the configured AK.

Downstream SoC components included in attestation Evidence are enumerated and classified as TCB or non-TCB by the integrator static attestation configuration described later in this document.

## Layered attestation model

This architecture follows the layered attestation model described in RATS architecture: a measured layer can become the attesting environment for a later layer.

Caliptra Core is the attesting environment for the MCU Runtime layer: it measures and authorizes MCU Runtime, and MCU Runtime identity is represented in the Caliptra DICE/DPE chain as the MCU Runtime DPE context.

After MCU Runtime is trusted and running, MCU Runtime becomes the attesting environment for downstream SoC components.

After MCU Runtime starts, it measures and authorizes SoC components using image metadata available through Caliptra Core. An integrator static attestation configuration in the MCU Runtime user app classifies each `fw_id` as SoC TCB or SoC non-TCB, selects the AK target, and defines the inventory claim scope.

SoC TCB components selected by the integrator configuration are represented as DPE contexts created or updated by MCU Runtime. SoC non-TCB component claims are stored in MCU-managed Software PCR Storage backed by access-protected MCU SRAM. MCU Runtime reads both sources to assemble OCP EAT claims and the `COSE_Sign1` envelope, then asks Caliptra Core to sign it using the configured AK.

![Layered attestation model](images/layered_attestation_model.svg)

## DPE context tree pattern

All device integrations share a common root chain managed by Caliptra:

```text
Root("RTMR")
 └─ CCIV("CCIV")
    └─ ROM_Stash_1..N
       └─ SoC_Manifest_Vendor("SOMV")
          └─ SoC_Manifest_Owner("SOMO")
             └─ MCU_RT("MCFW")
                └─ <integrator-selected SoC TCB context tree>
```

The chain above `MCU_RT` is common across integrations. Device-specific variation occurs below `MCU_RT`, where TCB components are arranged according to integrator static attestation configuration and the platform's attestation scenario.

| Level | DPE context | Description | Update and handle model |
| --- | --- | --- | --- |
| 0 | `Root("RTMR")` | DPE root context | Caliptra-managed lineage context; no MCU command handle. |
| 1 | `CCIV("CCIV")` | Caliptra Runtime context | Caliptra-managed lineage context; no MCU command handle. |
| 2 | `ROM_Stash_1..N` | ROM-stashed measurements | Caliptra-managed lineage context; immutable; no MCU command handle. |
| 3 | `SoC_Manifest_Vendor("SOMV")` | Vendor SoC manifest preamble | Caliptra-managed lineage context; replayed from vendor SoC manifest; no MCU command handle. |
| 4 | `SoC_Manifest_Owner("SOMO")` | Owner SoC manifest preamble | Caliptra-managed lineage context; replayed from owner SoC manifest; no MCU command handle. |
| 5 | `MCU_RT("MCFW")` | MCU Runtime context | Active; backdoor-updated by Caliptra RT; MCU holds the current handle. |
| 6 | `<integrator-selected SoC TCB contexts>` | Downstream SoC TCB contexts selected by integrator policy | Active; created or updated by MCU Runtime; MCU holds the current handles. |

Caliptra-managed lineage contexts are internal DPE state and are not command targets for MCU Runtime. MCU Runtime keeps all MCU-managed DPE contexts active and stores their current handles.

As MCU Runtime loads and verifies downstream SoC TCB components, it retains the parent context when deriving each child context so the parent remains usable for later derivation or update. Whenever DPE returns a new handle, MCU Runtime updates the stored handle before the next use.

## AK derivation principle

DPE derives attestation keys with `CertifyKey(handle)`. The CDI chain walks from the DPE root to the selected handle, incorporating each ancestor's TCI measurement. The SoC integration defines the AK target node as part of integrator static attestation configuration. The AK target is not selected dynamically at runtime.

| AK target | Derivation behavior |
| --- | --- |
| Platform / inventory AK target | If the configured AK target is `MCU_RT`, the AK is derived from the platform boot chain only: Root -> CCIV -> ROM-stashed measurements -> SoC Manifest -> MCU_RT. Downstream SoC TCB contexts can still be reported as OCP EAT claims, but they do not contribute to this AK. |
| Configured SoC AK target | If the configured AK target is a downstream SoC TCB node, the AK is derived from the path from root through MCU_RT to that node. |
Choosing the AK node controls which DPE ancestry contributes to AK derivation. DPE walks from the selected node upward to root. It does not include descendant contexts below the selected node. Descendant SoC component contexts can still be reported as OCP EAT claims.

| Evidence class | Conveying mechanism |
| --- | --- |
| TCB components on the AK lineage | DICE/DPE certificate chain |
| Integrator-selected TCB contexts outside the AK lineage | OCP EAT claims assembled by MCU Runtime |
| Non-TCB components | OCP EAT claims assembled by MCU Runtime from Software PCR Storage |

`CertifyKey` establishes the AK identity. MCU Runtime assembles OCP EAT claims and the COSE signing structure, then asks Caliptra Core to sign the corresponding bytes using the configured AK. Caliptra Core does not need to interpret the OCP EAT or COSE format.

## Integrator static attestation configuration

MCU Runtime uses integrator-provided static configuration to identify the SoC components included in attestation Evidence. For each `fw_id` listed in this configuration, the policy defines:

1. Whether the component is represented as DPE-backed TCI state or Software PCR Storage.
2. Whether the component is reported as OCP EAT inventory evidence.
3. Whether a DPE-backed component is the AK target.

A component contributes to the AK and DICE/DPE certificate chain only if it is on the selected AK context's ancestry path; DPE-backed TCB components outside that path can still be reported as OCP EAT inventory claims.

In this design, the policy and MCU-managed initial-load topology are static build-time configuration embedded in the MCU Runtime image and authenticated implicitly as part of MCU Runtime image verification.

Because hitless update preserves DPE Handle Storage and Software PCR Storage, the attestation policy and ordered MCU-managed initial-load topology must remain unchanged across a hitless update. MCU Runtime enforces this by comparing the `measurement_policy_digest` stored in preserved measurement metadata with the digest recomputed from the authenticated MCU Runtime image:

```text
measurement_policy_digest = SHA384(
    canonical_attestation_manifest_bytes ||
    canonical_ordered_soc_image_load_list_bytes
)
```

On mismatch, MCU Runtime enters an attestation error state. MCU Runtime can remain running to report the condition, but normal attestation Evidence and component measurement-state updates are disabled until cold boot reinitializes measurement state.

This check prevents preserved measurement state from being reused under a different policy or topology. For example, it prevents an update from changing TCB/non-TCB routing, AK target selection, inventory reporting scope, or MCU-managed DPE derivation order while reusing DPE handles and Software PCR records created under the previous policy/topology.

`GET_IMAGE_INFO(fw_id)` remains the source for image metadata used by authorization and loading. The integrator static attestation configuration is the source for attestation routing policy.

## Attestation scenarios

This architecture has one top-level attestation scenario:

1. **Inventory attestation**: Platform identity, SoC firmware measurements, configuration claims, and inventory claims for device owner or fleet-management verifiers.

Specific products such as management controllers, storage controllers, CPUs, and accelerators instantiate this scenario.

| Scenario | Verifier | Evidence focus | AK target |
| --- | --- | --- | --- |
| Inventory attestation | Device owner, fleet manager, platform operator | Platform identity and SoC inventory claims | Integrator-configured inventory or SoC TCB target |

## Inventory attestation

Inventory Evidence is assembled by MCU Runtime from two evidence pieces:

1. **DICE/DPE certificate chain**: Proves the lineage of the configured inventory AK target.
2. **OCP EAT**: Carries inventory claims for integrator-selected TCB components outside the AK lineage, plus non-TCB inventory claims read from Software PCR Storage.

TCB components on the AK lineage are not repeated as inventory claims in OCP EAT. The verifier appraises the DICE/DPE certificate chain and OCP EAT claims according to their claim class and provenance.

## Evidence verification model

A Verifier validates attestation Evidence in two stages: it first authenticates the device, then appraises the reported measurements.

1. **Authenticate the device**: Validate the DICE/DPE certificate chain to authenticate device identity and trust anchor.
2. **Authenticate the claims**: Validate the OCP EAT signature using the AK anchored in the authenticated DICE/DPE chain.
3. **Appraise current state**: Appraise `current` digests against reference values (for example, CoRIMs), endorsements, and verifier policy.
4. **Appraise journey state**: Appraise `journey` by replaying expected extensions and matching the reported journey digest.

The appraisal uses both the current and journey measurement values reported for each component:

| Value | What the Verifier establishes | How |
| --- | --- | --- |
| `current` | The device's current running state | Verifies current digests in EAT claims against reference values (for example, CoRIMs), endorsements, and verifier policy. |
| `journey` | The device's measurement history across hitless updates | Replays a log of the extended measurements and confirms it reproduces the reported journey digests. |

### Hitless update appraisal

During a hitless update, the `current` value reflects the newly accepted component image and the `journey` value folds the new measurement into the accumulated history. The Verifier uses the `current` digest to confirm the running image matches a reference value and/or policy, and the `journey` digest to confirm the device passed only through expected measurements since cold boot.

The DICE/DPE certificate chain authenticates the device, and the signed OCP EAT conveys the `current` and `journey` values. Journey appraisal requires a log of the extended measurements so the Verifier can interpret and replay the reported journey digests (see [Extended-measurement log](#extended-measurement-log)).

## Extended-measurement log

Appraising a `journey` measurement requires a log of the extended measurements that produced it: the Verifier replays the logged measurements and confirms they reproduce the reported journey digest. This applies wherever a measurement journey is appraised, so it is a general attestation concern, not specific to inventory attestation.

Generating and conveying this extended-measurement log is outside the scope of MCU Runtime and is yet to be defined. MCU Runtime does not produce this verifier replay log today.
