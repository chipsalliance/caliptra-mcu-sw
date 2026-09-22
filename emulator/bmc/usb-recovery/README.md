# USB Recovery Agent

`caliptra-mcu-usb-recovery` is a Linux recovery-agent application for the OCP
Secure Firmware Recovery interface exposed by the Caliptra USB device. Linux
performs standard USB enumeration and device setup; the application claims
interface 0 through libusb and performs OCP class control transfers.

The agent sends the recovery artifacts in the order requested by
`RECOVERY_STATUS`:

1. Caliptra FMC/runtime bundle (image index 0)
2. SoC manifest (image index 1)
3. MCU runtime (image index 2)

Images are streamed through the indirect FIFO CMS with FIFO status polling and
64-byte maximum USB control transfers. Each image is padded to a DWORD boundary
before transfer.

```bash
cargo run -p caliptra-mcu-usb-recovery -- \
  --caliptra-fmc-rt path/to/caliptra-fw.bin \
  --soc-manifest path/to/soc-manifest.bin \
  --mcu-runtime path/to/mcu-runtime.bin
```

The process needs permission to open the USB device. The integration test
`usbip_linux_libusb_lpcip_completes_recovery_boot` attaches the emulator's LPCIP
device through Linux USB/IP, grants temporary access to its `/dev/bus/usb` node,
runs this same agent implementation with built test artifacts, and checks the
MCU firmware boot-complete milestone.