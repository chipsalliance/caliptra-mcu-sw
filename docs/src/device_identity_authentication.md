# Caliptra Device Identity Authentication

## Purpose and scope

This document provides an overview of device identity authentication for a
Caliptra-integrated SoC and identifies the specifications that define its
certificate model, certificate store, and provisioning lifecycle.

A Caliptra integration provides identity, measured boot, and attestation
capabilities to the SoC. For device identity, Caliptra protects the identity
private key on behalf of the SoC. Private key material remains within the
Caliptra security boundary. The device uses the protected key to sign
attestation evidence presented to a remote verifier.

A certificate chain binds the corresponding public key to a PKI trust anchor.
To authenticate the evidence, the verifier validates the certificate chain
against a configured trust anchor and verifies the evidence signature using
the certified public key. Successful authentication establishes that the
evidence was signed with the corresponding private key; it does not establish
that the reported device state is acceptable. The verifier makes that
determination by evaluating the authenticated claims against its security
policy.

Device identity comprises two lifecycle activities:

- **Identity provisioning** establishes a Vendor, Owner, or Tenant
  endorsement for a device key.
- **Runtime authentication** has the device sign evidence with its identity
  key and present the corresponding certificate chain. The remote verifier
  validates that chain to a trusted root before evaluating the signed
  evidence.

The Caliptra device identity model and its integration are described by three
documents:

- [Caliptra Certificate Model](./certificate_model.md) defines the trust
  model, endorsement roles, certificate algorithms, and chain composition.
- [Caliptra MCU Certificate Store](./cert_store.md) defines the shared
  certificate-store architecture and platform-integrator configuration.
- [In-field Certificate Provisioning and
  Management](./certificate_provisioning.md) defines the Owner and Tenant
  provisioning lifecycle.

MCI certificate command codes are reserved in [External Mailbox
Commands](./external_mailbox_cmds.md), but their formats and implementation
are planned. SPDM certificate message formats are defined by the SPDM
specifications.
