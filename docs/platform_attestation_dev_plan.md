# Development Work Planning: Platform Attestation via Redfish

This document outlines the development plan for enabling platform attestation via Redfish on Hydra BMC. For the technical design, see [Platform Attestation via Redfish](platform_attestation_via_Redfish.md).

## Overview

The development is organized into three stages with the goal of delivering a **working prototype demo** showcasing platform attestation via Redfish with TIP signing. Target endpoints are **Overlake eRoT** and **Caliptra FPGA**.

1. **Stage 1**: Leverage NVIDIA's SPDM daemon to enable basic SPDM attestation for **Overlake eRoT**
2. **Stage 2**: Build Platform RoT attestation with TIP signing for **Overlake eRoT**
3. **Stage 3**: Enable **Caliptra FPGA** endpoint and complete multi-device platform attestation demo

### Parallel Workstream: Caliptra FPGA + DC-SCM Bringup

| Task | Duration | Notes |
|------|----------|-------|
| Caliptra FPGA + DC-SCM setup | TBD | Hardware setup, MCTP connectivity |
| Caliptra SPDM responder validation | TBD | SPDM handshake, measurement retrieval |

> **Note**: Caliptra FPGA bringup runs in parallel with Stages 1-2. Should be complete before Stage 3.

---

## Stage 1: SPDM Attestation for Overlake eRoT

**Goal**: Enable basic SPDM attestation via Redfish using NVIDIA's SPDM daemon with Overlake eRoT endpoint

**Estimated Duration**: 4 weeks (includes buffer for MCTP/transport debugging)

### Week-by-Week Tasks

| Week | Tasks | Deliverables |
|------|-------|--------------|
| **Week 1** | SPDM Daemon integration & build, MCTP transport configuration | SPDM daemon running |
| **Week 2** | MCTP debugging & validation, PLDM inventory integration | MCTP communication verified |
| **Week 3** | bmcweb ComponentIntegrity support | Device inventory, Redfish API (start) |
| **Week 4** | bmcweb ComponentIntegrity (complete), Overlake SPDM testing | **Redfish SPDM attestation with Overlake** |

---

## Stage 2: Platform RoT Attestation with TIP Signing

**Goal**: Implement compound measurement flow with TIP signing for Overlake eRoT

**Estimated Duration**: 3 weeks

### Week-by-Week Tasks

| Week | Tasks | Deliverables |
|------|-------|--------------|
| **Week 5** | TIP signing integration (cerberus_util), TIP certificate retrieval, Measurement aggregation logic | TIP signing operational |
| **Week 6** | Compound measurement D-Bus interface, GetPlatformCompoundMeasurements action, GetTIPCertificate endpoint | OEM Redfish actions functional |
| **Week 7** | Overlake end-to-end testing, Error handling, Documentation | **TIP-signed attestation with Overlake** |

---

## Stage 3: Enable Caliptra-FPGA Endpoint

**Goal**: Integrate Caliptra FPGA as second SPDM endpoint for multi-device attestation demo

**Estimated Duration**: 3 weeks (includes integration buffer)

### Week-by-Week Tasks

| Week | Tasks | Deliverables |
|------|-------|--------------|
| **Week 8** | Caliptra FPGA SPDM integration, Multi-device measurement collection | Caliptra measurements via Redfish |
| **Week 9** | Integration testing (Overlake + Caliptra), Bug fixes | Multi-device attestation working |
| **Week 10** | Demo preparation, Documentation, Buffer for issues | **Demo-ready prototype** |

---

## Timeline Summary

```
        Week 1-2  Week 3-4  Week 5    Week 6    Week 7    Week 8    Week 9    Week 10
        ┌─────────────────────────────────────────────────────────────────────────────┐
HW:     │          Caliptra FPGA + DC-SCM Bringup   │ Caliptra SPDM Validation        │
        └─────────────────────────────────────────────────────────────────────────────┘
        ┌───────────────────────┐ ┌───────────────────────┐ ┌─────────────────────────┐
SW:     │ Stage 1:              │ │ Stage 2: TIP Signing  │ │ Stage 3:                │
        │ Overlake SPDM         │ │ (Overlake)            │ │ Caliptra + Demo         │
        └───────────────────────┘ └───────────────────────┘ └─────────────────────────┘
                                ▲                         ▲                           ▲
                          Overlake SPDM           TIP-signed Overlake               DEMO
                          via Redfish               attestation             (Overlake + Caliptra)

Total Duration: 10 weeks (~2.5 months)
Demo Target: End of Week 10
```

### Key Dates (Starting Jan 26, 2026)

| Milestone | Week | Target Date |
|-----------|------|-------------|
| Overlake SPDM via Redfish | Week 4 | Feb 20, 2026 |
| TIP-signed Overlake attestation | Week 7 | Mar 13, 2026 |
| **Demo (Overlake + Caliptra)** | Week 10 | **Apr 3, 2026** |

### Demo Scope

| Feature | Status |
|---------|--------|
| SPDM measurements from Overlake eRoT | ✓ |
| SPDM measurements from Caliptra FPGA | ✓ |
| Compound measurement aggregation | ✓ |
| TIP-signed attestation response | ✓ |
| Redfish OEM API (GetPlatformCompoundMeasurements) | ✓ |
