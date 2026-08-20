# Attestation

The Caliptra attestation architecture defines how Caliptra Core and MCU Runtime establish device identity, measure downstream SoC components, and produce Evidence that lets Verifiers appraise comprehensive device state.

Caliptra Core remains the hardware root of trust. It owns the DICE/DPE context chain and protects DPE state and attestation key material. Caliptra Core first attests MCU Runtime by measuring and authorizing it. After MCU Runtime is trusted and running, MCU Runtime acts as the attesting environment for downstream SoC firmware components, assembles the Evidence, and asks Caliptra Core to sign it using the configured AK.

## Documents

| Document | Purpose |
| --- | --- |
| [Design Specification](./attestation-design.md) | Defines the Caliptra Subsystem attestation model, evidence sources, DPE topology, and OCP EAT evidence flow. |
| [Measurement API](./attestation-measurement-api.md) | Defines the MCU Runtime measurement API used by image loading, firmware update, and SPDM evidence generation. |
| [Static Integrator Configuration](./static_integrator_configuration.md) | Defines the integrator-owned static configuration artifacts used by image loading and attestation, including the SoC/Auth Manifest metadata, Attestation Manifest, and SoC image load list. |
| [Tock Capsules](./attestation-tock-capsules.md) | Defines the reserved SRAM partitioning, syscall drivers, and record formats used to store downstream SoC component attestation records in DPE Handle Storage and Software PCR Storage. |
| [Attestation Integration Guide](./attestation-integrator-guide.md) | Describes platform integration requirements, including integrator static attestation configuration, reserved SRAM sizing, dummy SoC images, and SPDM/OCP EAT integration. |

## Relationship to SPDM

MCU Runtime produces one attestation report: the signed OCP EAT. SPDM only carries that report to the requester; no additional SPDM attestation report is created or included inside it. The MCU mailbox provides another retrieval path for the same report.

The requester boundary differs by transport:

* BMC/pRoT style requesters use SPDM over MCTP.
* PCIe DOE requesters, such as confidential-compute PCIe devices, use SPDM over DOE.
* SoC-local requesters, such as an AP OS or TEE, can use the MCU mailbox path.

SPDM can carry the signed OCP EAT in two ways:

1. `GET_MEASUREMENTS` returns the signed OCP EAT in measurement block index `0xFD`.
2. The Caliptra `GET_ATTESTATION` command can be carried as an SPDM VDM command.

The MCU mailbox path can also expose Caliptra `GET_ATTESTATION` for SoC-local requesters. The Evidence describes device identity and inventory claims for downstream SoC components.

The attestation design is broader than any one transport: it covers measurement collection, persistent measurement state, DPE context handle management, Software PCR-style storage, integrator static attestation configuration, and OCP EAT claim assembly. Transport-facing APIs consume the measurement API output and package the resulting claims as signed Evidence. SPDM transport details are described in [SPDM](./spdm.md).
