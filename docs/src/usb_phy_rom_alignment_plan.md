# USB PHY Emulation and ROM Alignment Plan

## Purpose

This document records the plan to align the MCU ROM USB initialization and emulator behavior with the current Caliptra SS USB architecture and the external Microchip USB3320 ULPI PHY used by the Janus FPGA platform.

The plan builds on the existing [USB Recovery Emulation Design](./usb_recovery_emulation.md). It preserves USB/IP as the host-facing transport while adding the software-visible behavior of an external ULPI PHY and correcting the Device 0 OCP Recovery path.

## Current architecture

The physical path is:

```text
Recovery Agent
  -> host USB stack and controller
  -> USB cable
  -> USB3320 PHY
  -> ULPI
  -> Caliptra SS compound USB controller
  -> Device 0 EP0 classifier
       -> standard request: legacy DMA and MCU ROM
       -> OCP Recovery request: hardware recovery registers and FIFO
```

The USB3320 handles the electrical USB interface and translates it to ULPI. It does not process URBs, descriptors, or OCP commands. URBs exist in the host software stack; the Caliptra SS controller receives USB packets produced from those URBs.

The compound controller contains Device 0, Device 1, hub support, packet memories, and hardware-assisted OCP Recovery. OCP Recovery is claimable only on Device 0 EP0. The current top-level disables hub mode, so Device 0 is the upstream device.

### FPGA two-device hub bring-up

The FPGA ROM `test-lpcip-usb-ocp-recovery` path now selects hub mode in software
and enumerates its internal devices sequentially:

1. Disable Device 1's controller and connection before initializing Device 0.
2. Initialize the shared PHY and hub, connect Device 0, and service its standard
   EP0 requests until `SET_CONFIGURATION(1)` completes.
3. Initialize Device 1's separate endpoint list and packet buffers, enable and
   connect it, and service its EP0 requests until it is configured.

This requires MCU access to the Device 1 CSR and packet-memory windows configured
at `0xa440_0000` and `0xa450_0000` on the FPGA. Device 1 is normally SoC-owned;
SoC firmware must not drive it concurrently with this test. Device 0 remains
connected, with its OCP recovery descriptors and hardware path unchanged.
Device 1 uses a test-only VID:PID `0000:0001`, one vendor-specific interface,
and no endpoints beyond EP0; it does not expose OCP recovery.

Build with:

```sh
cargo xtask rom-build --platform fpga --features test-lpcip-usb-ocp-recovery
```

UART logs identify each device's SETUP packets and enumeration completion.
The ROM proceeds to recovery after both devices have configured; it waits for
Device 1 if the host does not configure it. This is an initial-enumeration test,
not a persistent Device 1 function driver: later requests and re-enumeration
after a reset are not serviced once this routine returns. The emulator ROM
retains its Device 0-only path because its Device 1 model is a register stub.

## Current gaps

### Emulator

The Linux integration path already exercises:

```text
libusb -> Linux USB core -> VHCI -> USB/IP -> emulator
```

Below the USB/IP adapter, however, the model is transaction-level:

- standard EP0 requests are translated directly into LPCIP descriptor and register events;
- OCP requests are offered directly to `UsbRecoveryHost` before reaching the LPCIP Device 0 path;
- `ULPIDEBUG` has no USB3320 transaction behavior;
- no PHY identity, scratch register, Function Control, OTG Control, or ULPI access completion is modeled; and
- the mirrored-SETUP classifier and ownership transition are not represented as one unified path.

Consequently, the current end-to-end test validates the recovery agent, USB/IP, ROM enumeration, and recovery data flow, but it does not validate the ROM's external-PHY initialization or the hardware's Device 0 EP0 claim boundary.

### ROM

The LPCIP ROM driver initializes Device 0 and enumerates the OCP interface, but it assumes that the platform has already enabled and released reset for the external PHY and controller clock. It does not currently:

- verify that the controller reports ULPI support;
- select ULPI mode through `ULPIDEBUG`;
- verify the USB3320 vendor and product IDs;
- configure USB3320 Function Control and OTG Control;
- run the USB3320 Scratch-register test; or
- explicitly represent the platform PHY-reset and clock contract.

The existing Device 0 SRAM and register initialization must remain based on the current Caliptra SS programming model. Old Janus addresses and FPGA-specific register interpretations must not be copied into ROM.

## Design decision

The emulator will implement a behavioral USB3320 and ULPI register gateway, not pin-cycle ULPI or analog USB signaling.

The behavioral model will validate the same firmware-visible contract used on FPGA:

- `ULPIDEBUG.PHY_MODE` selection;
- ULPI register reads and writes;
- `PHY_ACCESS` completion;
- USB3320 identification registers;
- Function Control, OTG Control, and Scratch behavior;
- VBUS presence and selected operating speed; and
- controller attach only after PHY and Device 0 initialization.

The model will continue to translate USB/IP control URBs into transaction-level USB operations. It will not model the ULPI 60 MHz waveform, D+/D- electrical behavior, PID encoding, CRC generation, bit stuffing, chirp timing, signal integrity, or compliance behavior.

## Ownership split

### Platform integration

Platform code owns operations that are outside the USB controller register contract:

- routing ULPI pins;
- asserting and releasing USB3320 `RESETB`;
- providing or accepting the 60 MHz ULPI clock;
- releasing controller reset and clock gating; and
- reporting that the PHY is ready before ROM uses the controller.

The emulator represents this contract through initial PHY/reset/clock state rather than board GPIOs.

### MCU ROM

ROM owns software-visible USB initialization:

1. Confirm that Device 0 reports ULPI support.
2. Select the ULPI interface through `ULPIDEBUG.PHY_MODE`.
3. Read and verify the USB3320 vendor and product IDs.
4. Run the USB3320 Scratch write, set, clear, and readback test.
5. Configure Function Control for high-speed peripheral operation.
6. Configure OTG Control for device mode without host pull-downs or VBUS drive.
7. Keep Device 0 disconnected while clearing controller and interrupt state.
8. Initialize the endpoint command/status list and EP0 buffers in Device 0 packet SRAM.
9. Program `EPLISTSTART` and `DATABUFSTART` according to the current local packet-memory contract.
10. Enable only the required Device 0 interrupts.
11. Enable the controller, preserve the required disconnect interval, and then assert `DCON`.
12. Service standard enumeration until configuration is complete.
13. Leave claimed OCP DATA and STATUS stages to the hardware recovery path.

The ROM implementation should use the generated Caliptra SS register fields. It must not copy the old Janus `0x4940_0000` controller address, `0x2400_2000` DMA address, host `PORTMODE` dependency, or FPGA-specific `PLLON` aliases.

### Platform USB memory maps

The emulator, the Caliptra HTG940 FPGA platform, and the NXP Janus FPGA do not
share one MCU address map. ROM and test firmware must select the appropriate
platform mapping rather than using the generated emulator addresses directly.

| Region | NXP Janus FPGA | Current emulator | Caliptra HTG940 FPGA |
| --- | ---: | ---: | ---: |
| MCU ROM | `0x8000_0000`, 256 KiB | `0x8000_0000`, 128 KiB | `0xb004_0000`, 128 KiB |
| MCU SRAM | `0x2200_0000`-`0x223f_ffff`, four 1 MiB banks | `0x4000_0000`, 1 MiB | `0xa8c0_0000`, 512 KiB |
| USB Device 0 / combo registers | `0x4940_0000`, 4 KiB | `0x2000_0000` compound aperture | `0xa420_0000` |
| USB OCP Recovery registers | `0x4940_2000`, 4 KiB | `0x2000_0800`, inside the compound aperture | `0xa420_0800` |
| USB Device 0 packet SRAM | `0x2400_2000`, 8 KiB | `0x3000_0000`, 64 KiB | `0xa430_0000` |
| USB Device 1 registers | Not listed | `0x2000_2000` | `0xa440_0000` |
| USB Device 1 packet SRAM | Not listed | `0x3001_0000`, 64 KiB | `0xa450_0000` |
| USB host registers | `0x4940_1000`, 4 KiB | Not mounted in the current SoC map | Not listed |

Caliptra core ROM is not the `MCU ROM` row above. It remains in the Caliptra
core's private address space at `0x0000_0000` with the size defined by the
selected Caliptra ROM build (currently 96 KiB).

Platform code should select these bases through platform-specific constants or
injected register-block references. The HTG940 constants live in
`platforms/fpga/config`; they must not change the generated Caliptra SS map
globally, because emulator and Caliptra SS RTL tests depend on that map. Hardware
preflight must still verify the synthesized address map before loading firmware;
matching register layouts do not imply matching absolute addresses or aperture
sizes. The published HTG940 map does not specify USB aperture sizes, so firmware
must not infer them from the spacing between base addresses.

### OCP recovery hardware model

The emulator's Device 0 path will mirror the RTL ownership rules:

1. Every Device 0 EP0 SETUP reaches the legacy LPCIP/DMA model.
2. The same completed eight-byte SETUP is classified for OCP Recovery.
3. A valid enabled OCP request claims subsequent DATA, STATUS, and PING stages.
4. Claimed requests use the recovery register or FIFO model without per-command MCU handling.
5. Standard and non-OCP requests remain owned by ROM.
6. Bus reset, Device 0 reset/disconnect, replacement SETUP, or explicit claim abort releases recovery ownership as defined by the RTL contract.

## Implementation phases

### Phase 1: USB3320 behavioral model

Status: complete as of 2026-09-25.

- Add a USB3320 register file and reset defaults to the emulator peripheral.
- Implement ULPI read/write transactions initiated through Device 0 `ULPIDEBUG`.
- Clear `PHY_ACCESS` when each modeled transaction completes.
- Implement vendor ID, product ID, Function Control, OTG Control, Scratch, SET, and CLEAR aliases.
- Add focused tests for identification, read/write completion, Scratch behavior, reset state, and invalid accesses.

The implementation is in `emulator/periph/src/usb.rs`. It models synchronous
gateway completion, fixed USB3320 identification, writable control registers,
read-only identification registers, Function Control soft reset, and the ULPI
write/set/clear aliases used by the NXP initialization sequence. The complete
`caliptra-mcu-emulator-periph` test suite validates this phase.

### Phase 2: ROM PHY initialization

Status: complete as of 2026-09-25.

- Add a small no-allocation USB3320 driver around the generated `ULPIDEBUG` register.
- Add bounded polling and explicit errors for timeout, identity mismatch, and Scratch failure.
- Add a platform-ready contract for external reset and clock setup.
- Reorder controller initialization so attach occurs only after PHY, packet memory, EP0, and interrupt state are valid.
- Preserve the current OCP descriptors and standard enumeration behavior.

The LPCIP ROM driver now checks Device 0 ULPI support, selects ULPI mode, verifies
the USB3320 vendor and product IDs, exercises the Scratch write/set/clear aliases,
and configures high-speed peripheral Function Control and device-mode OTG Control.
Each gateway access uses bounded `PHY_ACCESS` polling, and PHY failures prevent
Device 0 from attaching. The platform contract remains explicit: pin routing,
external reset release, and the 60 MHz controller/PHY clock must be ready before
`init_and_enumerate` is called. A ROM hardware-model test verifies the final PHY
state at Device 0 attach.

### Phase 3: Unified Device 0 and OCP path

Status: complete as of 2026-09-25.

- Route every USB/IP EP0 SETUP through the LPCIP Device 0 model first.
- Move OCP classification into the modeled post-SETUP arbitration point.
- Replace the USB/IP adapter's direct pre-controller `UsbRecoveryHost` dispatch.
- Model claimed DATA and STATUS ownership, STALL, replacement SETUP, reset, and abort behavior.
- Keep the recovery register/FIFO implementation shared with Caliptra event handling.

The USB/IP adapter now deposits every LPCIP SETUP in Device 0 packet memory
before invoking the OCP classifier. Non-OCP requests continue through the ROM
endpoint path without duplicate SETUP delivery, while claimed OCP requests use
the shared recovery register and FIFO model for their transaction-level DATA
and STATUS handling. The peripheral tracks claim and persistent protocol-STALL
ownership and releases it on a successful replacement SETUP, USB bus reset,
Device 0 disconnect/reset, path disable, or firmware `OCP_CLAIM_ABORT`.

Focused tests cover ownership transitions and verify that a claimed OCP SETUP
is visible in the physical Device 0 SETUP buffer. The USB/IP integration test
mixes ROM-owned enumeration with hardware-owned OCP register and FIFO traffic.
Packet retries and PING remain abstracted inside transaction-level completion;
pin-cycle USB and ULPI timing remain outside the emulator model by design.

### Phase 4: End-to-end and FPGA parity

- Run existing LPCIP enumeration and recovery unit tests.
- Run the Linux `libusb` over USB/IP streaming-boot test.
- Add negative tests for PHY identity failure, ULPI timeout, Scratch failure, disabled OCP path, malformed OCP SETUP, reset during a claim, and non-OCP class requests.
- Compare ROM register traces against the NXP bring-up sequence and current Caliptra SS programmer's guide.
- Select the HTG940 platform USB bases and confirm the synthesized register and packet-RAM aperture sizes before loading ROM or test firmware.
- Run the same recovery-agent image sequence against FPGA hardware through the USB3320 daughtercard.

## Acceptance criteria

The work is complete when:

1. ROM refuses to attach Device 0 if external-PHY initialization fails.
2. The emulator executes and validates the same USB3320 register sequence as FPGA firmware.
3. Standard enumeration still traverses Device 0 and ROM.
4. Valid OCP Recovery requests traverse Device 0 SETUP handling and are then claimed by the hardware recovery model.
5. Non-OCP requests never enter the recovery model.
6. Existing USB/IP and direct emulator tests pass without a host-agent API change.
7. The production-style `libusb` recovery agent completes streaming boot against both the emulator and FPGA.
8. Remaining differences are limited to explicitly excluded PHY electrical and timing behavior.

## References

- [USB Recovery Emulation Design](./usb_recovery_emulation.md)
- Caliptra SS USB2 Programmer's Guide: `hw/caliptra-ss/third_party/usb2/docs/USB2_Programmers_Guide.md`
- Caliptra SS OCP Recovery microarchitecture: `hw/caliptra-ss/docs/usb2_recovery_spec/README.md`
- Current ROM LPCIP driver: `platforms/common/usb/src/lpcip.rs`
- Current emulator USB compound peripheral: `emulator/periph/src/usb.rs`
- USB/IP adapter: `tests/integration/src/usb/hwmodel.rs`
- NXP USB3320 reference initialization: `janus_fpga_sw/janus_fpga_sw/middleware/usb/phy/USB3320_phy.c`
