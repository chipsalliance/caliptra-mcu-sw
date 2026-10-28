# LPCIP Device 0 emulation

The `latest` hardware revision includes a behavioral Device 0 controller at
`USB_COMBO_ADDR` and shared 64 KiB packet SRAM at `USB_DEV0_MEM_ADDR`. The
standalone emulator and `ModelEmulated` expose its cloneable
`lpcip_usb_host_controller`. The existing OpenTitan USBDEV controller and
`usb_host_controller` remain separate and available; 2.1 is unchanged.

## Host interface

After firmware enables and connects Device 0:

1. Call `set_vbus(true)` to supply host VBUS.
2. Wait for `connected()`, stepping the emulator with a bounded timeout.
3. Call `bus_reset(LpcipUsbSpeed::Full)` or `High`.
4. Send eight-byte SETUP packets with `host_setup(address, &setup)`.
5. Transfer individual packets with `host_in(address, endpoint)` and
   `host_out(address, endpoint, &data)`.

Successful transactions are ACKed. `Nak` means retry after giving firmware time
to run; `Stall` is an endpoint halt. `Disconnected`, `AddressMismatch`,
`InvalidEndpoint` and `EndpointDisabled` distinguish absent/nonresponding
targets. Invalid DMA addresses, oversized packets and malformed SETUP packets
return explicit errors without completing or consuming their descriptors.
`host_sof` updates the frame number and frame interrupt.

Host methods never execute firmware or synthesize standard-request responses.
Enumeration, unsupported-request policy and response bytes belong to firmware.
The host interface addresses Device 0 directly, not the upstream hub.

## Firmware contract

- `EPLISTSTART` is 256-byte aligned; `DATABUFSTART` is 128 KiB aligned.
  Descriptor and data accesses must resolve into the same bounded packet SRAM
  exposed through CPU MMIO. The generated CPU aperture accepts aligned words.
- Each physical endpoint has two descriptor words. Physical endpoint
  `2 * endpoint + direction` uses direction zero for OUT and one for IN.
  EP0 OUT's second word points to the eight-byte SETUP buffer.
- Descriptors encode ACTIVE at bit 31, DISABLED at 30, STALL at 29,
  toggle reset/value at 28/27, periodic at 26, remaining bytes at 25:11,
  and a 64-byte buffer offset at 10:0.
- Firmware publishes payload and descriptor contents before handing ownership
  to the controller with ACTIVE. Packet completion updates the residual length
  and buffer offset. ACTIVE clears and the endpoint interrupt sets when the
  transfer completes, including a short OUT packet. Noncontrol double-buffer
  endpoints alternate banks only on completion.
- Following the selected RTL, STALL is effective only with ACTIVE clear.
  DISABLED is ignored for EP0. SETUP sets EP0 data toggles to DATA1 and holds
  EP0 traffic until firmware acknowledges SETUP with W1C. A replacement SETUP
  overwrites the SETUP buffer, but does not erase old IN/OUT descriptors.
  Firmware must cancel/rearm them before clearing SETUP; EPSKIP returns the
  selected descriptor's ownership without erasing its payload.
- Address writes stage an additional accepted token address. In the selected
  `usb_reg_if.m.vhdl`, **the next SETUP latches its token address into both
  address registers**. Consequently readback can retain the old address after
  the status IN packet. This follows the selected RTL, rather than the generated
  field description that currently describes a status-stage commit.
- Bus reset resets addresses and toggles and raises reset-change/device
  interrupt status. It does not erase packet SRAM or firmware descriptors.
  MCU peripheral reset resets CSRs while retaining SRAM and external VBUS.
- INTSTAT and device change bits are independently W1C; INTSETSTAT sets
  interrupt status. INTEN and INTROUTE select pending IRQ/FIQ sources.
  IRQ is sampled on peripheral polling and shares the existing emulator USB
  interrupt line without dropping pending legacy USB interrupts.
  FIQ pending state is exposed through `fast_interrupt_pending()`; no separate
  MCU FIQ connection is modeled.

## Deliberate limits

Device 1 and its memory use explicitly unsupported, non-storing adapters.
Hub, PHY, LPM/suspend and OCP-recovery registers retain nonfunctional trait
handlers, not generated stateful implementations. Enable emulator register-stub
warnings to identify firmware accesses to these surfaces. There is no hub
enumeration, PHY signaling, automatic OCP request interception or USB/IP server.
Bulk and interrupt packets support full/high speed; isochronous descriptors
return `UnsupportedTransfer` rather than claiming timing-correct ISO behavior.

## Validation

```sh
cargo test -p caliptra-mcu-emulator-periph usb:: --lib
cargo test -p caliptra-mcu-hw-model test_lpcip_standard_request_requires_firmware_service --lib
```

The first suite exercises firmware MMIO, descriptors, enumeration, ownership,
reset, SETUP replacement, packet bounds and interrupt semantics. The hardware
model test runs a minimal RISC-V ROM that polls SETUP and publishes a descriptor,
proving that repeated host transactions alone cannot service a standard request.
