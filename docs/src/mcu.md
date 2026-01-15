# Caliptra Manufacturer Control Unit (MCU) Firmware and SDK

*Spec revision: 0.9*

The Caliptra MCU firmware is be provided as a reference software development kit (SDK) with a consistent foundation for building a quantum-resilient and standards-compliant Root of Trust (RoT) for SoC implementers. It extends the Caliptra core system to provide the Caliptra Subsystem set of services to the encompassing system.

While Caliptra Core provides support for Identity, Secure Boot, Measured Boot, and Attestation, the Caliptra MCU firmware will be responsible for enabling Recovery, RoT Services, and Platform integration support. All SoC RoTs have specific initialization sequences and scenarios that need to be supported beyond standard RoT features. Hence, the MCU firmware will be distributed as Rust SDK with batteries included to build RoT Applications.

The Caliptra MCU SDK is composed of two major parts:

**ROM**:  When the MCU first boots, it executes a small, bare metal ROM. The ROM is responsible for sending non-secret fuses to Caliptra core so that it can complete booting. The MCU ROM will be silicon-integrator-specific. However, the MCU SDK will provide a ROM framework that binds the MCU and Caliptra. The ROM will also be used with the software emulator, RTL Simulator, and FPGA stacks. For more details, see the [ROM specification](rom.md).

**Runtime**: The majority of the MCU firmware SDK is the runtime firmware, which provides the majority of the services after booting. Most of the documentation here consists of the documentation for the runtime.

![MCU Diagram](images/mcu_stack.svg)

## Principles

Caliptra 2.x firmware aspires to be the foundation for the RoT used in SoCs integrating Caliptra. Hence architecture, design and implementation must abide by certain guiding principles. Many of these principles are the founding principles for the Caliptra Project.

The MCU firmware SDK will follow the same principles as the Caliptra core's firmware.

* **Open and Extensible**: The MCU SDK is published as open source and available via GitHub, and uses a build toolchain for repeatable builds. The MCU SDK provided is a reference implementation, and is intended to be extended and adaptable by integrators.

* **Consistent**: Vendors require features like Identity, Secure Boot, Measured Boot, Attestation, Recovery, Update, Anti-Rollback, and ownership transfer. There are standards defined by various organizations around these feature areas. The MCU SDK will follow TCG, DMTF, OCP, PCIe and other standards to guarantee consistency on RoT features and behavior.

* **Compliant**: The MCU SDK must be compliant with security standards and audits. Security audits will be performed and audit reports will be published on GitHub. In addition, the SDK will also be audited for OCP SAFE and short form reports will be published to GitHub.

* **Secure and Safe Code**: The MCU SDK will follow the standards in Caliptra Core for security and memory safety as first principle and will be implemented in Rust.

## SDK Features

The following sections give a short overview of the features and goals of the MCU SDK.

### Development

Software emulators for Caliptra, MCU, and a reference SoC will be provided as part of the MCU SDK. Software emulators will be an integrated part of CI/CD pipelines. In addition, Caliptra also has RTL Simulators based on Verilator that can be used for regression testing. The Caliptra hardware team also has reference hardware running on FPGA platforms.

### RTOS

MCU provides various simultaneous, complex RoT services. Hence an RTOS is needed. As the MCU SDK is implemented in Rust, we need Rust-based RTOS. MCU will leverage the Tock Embedded Operating System, an RTOS designed for secure embedded systems. MCU uses the Tock Kernel while providing a Caliptra async user mode API surface area. Tock provides a good security and isolation model to build an ROT stack.

### Drivers

Tock has a clean user and kernel mode separation. Components that directly access hardware and provide abstractions to user mode are implemented as Tock drivers and capsules (kernel modules). The MCU SDK will provide the following drivers:

* UART Driver
* I3C Driver
* Fuse Controller Driver
* Caliptra Mailbox Driver
* MCI Mailbox Driver
* SPI Flash Driver (may be replaced by a silicon-specific flash driver)

Silicon integrators may provide their own drivers to implement SoC-specific features that are not provided by the MCU SDK. For example, if an SoC implements TEE-IO, the silicon vendor will be responsible for providing PCIe IDE and TDISP drivers.

### Stacks

As the Caliptra RoT is built on the foundation of industry standard protocols, the MCU SDK will provide the following stacks:

* MCTP
* PLDM
* PLDM Firmware Update
* OCP Streaming Boot
* SPDM based Attestation
* PCIe IDE
* TDISP
* SPI Flash Boot

### APIs and Services

Caliptra RoT will provide common foundational services and APIs required to be implemented by all RoT. The following are the APIs and services provided by MCU SDK:

* Image Loading
* Attestation
* Signing Key management and revocation
* Anti-Rollback protection
* Firmware Update
* Life Cycle Management
* Secure Debug Unlock
* Ownership Transfer
* Cryptographic API
* Certificate Store
* Key-Value Store
* Logging and Tracing API

### Applications

Each SoC has unique features and may need a subset of security services. Hence silicon integrators will be responsible for authoring ROT applications leveraging MCU SDK. MCU SDK will ship with a set of applications that will demonstrate the features of the MCU SDK.

### Tooling and Documentation

The MCU SDK will feature

* Repeatable build environments to build RoT Applications
* Image generation, verification, and signing tools
* Libraries for interacting with Caliptra ROT to perform various functions like attestation, firmware updates, log retrieval, etc.
* An MCU SDK Architecture and Design Specifications
* An MCU SDK Developers' Guide
* An MCU SDK Integrators' Guide
* The MCU SDK API