# `caliptra-mcu-usb-recovery`

Host-side Caliptra 2.2 OCP USB Recovery v1.1 protocol driver (`RecoveryAgent`
and `RecoveryTransport`) and optional `libusb` transport (`LibusbTransport`).

## Building

The core library has no default `libusb` dependency so tests and custom
transports can implement `RecoveryTransport` directly. Enable the `libusb`
feature to build `LibusbTransport` (`rusb` vendors the `libusb` C sources):

```sh
cargo build --locked -p caliptra-mcu-usb-recovery --features libusb
```

## Protocol Overview

- **`RecoveryTransport`** defines OCP class control IN/OUT transfers (`read` and
  `write`).
- **`RecoveryAgent::probe`** reads `PROT_CAP` and `DEVICE_STATUS` and returns
  the reported protocol version, CMS region count, and device status.
- **`RecoveryAgent::poll`** advances recovery without sleeping: it streams
  firmware images requested via `RECOVERY_STATUS` (`0` = Caliptra FMC/runtime,
  `1` = SoC manifest, `2` = MCU runtime) into the indirect FIFO
  (`INDIRECT_FIFO_CTRL` / `INDIRECT_FIFO_DATA`), activates each image via
  `RECOVERY_CTRL`, and returns `Poll::Pending` whenever the device is busy so
  the caller can perform its own wait until `Poll::Ready` is returned.
- Individual FIFO data writes are bounded to 64 bytes, the device-reported max
  transfer size, and available FIFO capacity, with zero-padding applied to the
  final DWORD when an image length is not a multiple of 4 bytes.
