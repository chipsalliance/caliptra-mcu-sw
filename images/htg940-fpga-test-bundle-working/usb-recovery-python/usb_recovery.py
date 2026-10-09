# Licensed under the Apache-2.0 license

"""OCP Secure Firmware Recovery agent using PyUSB."""

from __future__ import annotations

import argparse
import enum
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

import usb.core
import usb.util

if sys.platform == "win32":
    import libusb_package


DEFAULT_VENDOR_ID = 0x0424
DEFAULT_PRODUCT_ID = 0x0007
INTERFACE = 0
REQUEST_TYPE_IN = 0xA1
REQUEST_TYPE_OUT = 0x21
REQUEST = 0
USB_CONTROL_MAX_BYTES = 64
PROT_CAP_MAGIC = b"OCP RECV"


class RecoveryError(RuntimeError):
    """Raised when the device reports an invalid or failed recovery state."""


class RecoveryCommand(enum.IntEnum):
    PROT_CAP = 0x22
    DEVICE_STATUS = 0x24
    RECOVERY_CTRL = 0x26
    RECOVERY_STATUS = 0x27
    INDIRECT_FIFO_CTRL = 0x2D
    INDIRECT_FIFO_STATUS = 0x2E
    INDIRECT_FIFO_DATA = 0x2F


class DeviceStatus(enum.IntEnum):
    STATUS_PENDING = 0x0
    DEVICE_HEALTHY = 0x1
    DEVICE_ERROR = 0x2
    RECOVERY_MODE = 0x3
    RECOVERY_PENDING = 0x4
    RUNNING_RECOVERY_IMAGE = 0x5
    BOOT_FAILURE = 0xE
    FATAL_ERROR = 0xF


class DeviceRecoveryStatus(enum.IntEnum):
    NOT_IN_RECOVERY = 0x0
    AWAITING_IMAGE = 0x1
    BOOTING_IMAGE = 0x2
    SUCCESS = 0x3
    FAILED = 0xC
    AUTHENTICATION_ERROR = 0xD
    ERROR_ENTERING_RECOVERY = 0xE
    INVALID_CMS = 0xF


class RecoveryTransport(Protocol):
    def read(self, command: RecoveryCommand, length: int) -> bytes:
        """Read one OCP Recovery command response."""

    def write(self, command: RecoveryCommand, data: bytes) -> None:
        """Write one OCP Recovery command payload."""


class PyUsbTransport:
    def __init__(self, device: usb.core.Device, timeout_ms: int) -> None:
        self._device = device
        self._timeout_ms = timeout_ms
        self._claimed = False

    @classmethod
    def open(
        cls,
        vendor_id: int,
        product_id: int,
        discovery_timeout: float,
        transfer_timeout: float,
    ) -> PyUsbTransport:
        deadline = time.monotonic() + discovery_timeout
        device = None
        while device is None:
            if sys.platform == "win32":
                device = libusb_package.find(
                    idVendor=vendor_id, idProduct=product_id
                )
            else:
                device = usb.core.find(idVendor=vendor_id, idProduct=product_id)
            if device is not None:
                break
            if time.monotonic() >= deadline:
                raise RecoveryError(
                    f"USB recovery device {vendor_id:04x}:{product_id:04x} was not found"
                )
            time.sleep(0.02)

        transport = cls(device, round(transfer_timeout * 1000))
        try:
            usb.util.claim_interface(device, INTERFACE)
            transport._claimed = True
        except usb.core.USBError as error:
            usb.util.dispose_resources(device)
            raise RecoveryError(
                "failed to claim OCP Recovery USB interface"
            ) from error
        return transport

    def close(self) -> None:
        if self._claimed:
            usb.util.release_interface(self._device, INTERFACE)
            self._claimed = False
        usb.util.dispose_resources(self._device)

    def __enter__(self) -> PyUsbTransport:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def read(self, command: RecoveryCommand, length: int) -> bytes:
        try:
            response = self._device.ctrl_transfer(
                REQUEST_TYPE_IN,
                REQUEST,
                int(command),
                INTERFACE,
                USB_CONTROL_MAX_BYTES,
                timeout=self._timeout_ms,
            )
        except usb.core.USBError as error:
            raise RecoveryError(
                f"OCP {command.name} read failed: {error}"
            ) from error
        return bytes(response[:length])

    def write(self, command: RecoveryCommand, data: bytes) -> None:
        try:
            written = self._device.ctrl_transfer(
                REQUEST_TYPE_OUT,
                REQUEST,
                int(command),
                INTERFACE,
                data,
                timeout=self._timeout_ms,
            )
        except usb.core.USBError as error:
            raise RecoveryError(
                f"OCP {command.name} write failed: {error}"
            ) from error
        if written != len(data):
            raise RecoveryError(
                f"short OCP {command.name} write: {written} of {len(data)} bytes"
            )


@dataclass(frozen=True)
class RecoveryImages:
    caliptra_fmc_rt: bytes
    soc_manifest: bytes
    mcu_runtime: bytes

    def get(self, index: int) -> bytes:
        images = (self.caliptra_fmc_rt, self.soc_manifest, self.mcu_runtime)
        try:
            return images[index]
        except IndexError as error:
            raise RecoveryError(
                f"device requested unsupported recovery image index {index}"
            ) from error

    @staticmethod
    def name(index: int) -> str:
        names = ("Caliptra FMC/runtime", "SoC manifest", "MCU runtime")
        try:
            return names[index]
        except IndexError:
            return "unknown image"


@dataclass(frozen=True)
class FifoStatus:
    full: bool
    write_index: int
    read_index: int
    size_dwords: int
    max_transfer_dwords: int

    def available_dwords(self) -> int:
        if self.full or self.size_dwords == 0:
            return 0
        if self.write_index >= self.read_index:
            used = self.write_index - self.read_index
        else:
            used = self.size_dwords - (self.read_index - self.write_index)
        return max(self.size_dwords - used, 0)


class RecoveryAgent:
    def __init__(
        self,
        transport: RecoveryTransport,
        poll_interval: float = 0.01,
        state_timeout: float = 30.0,
    ) -> None:
        self.transport = transport
        self.cms = 0
        self.poll_interval = poll_interval
        self.state_timeout = state_timeout

    def run(self, images: RecoveryImages) -> None:
        log("Checking device capabilities")
        self._check_capabilities()
        log("Waiting for recovery mode")
        startup_deadline = time.monotonic() + self.state_timeout
        while True:
            status = self._device_status()
            if status == DeviceStatus.RECOVERY_MODE:
                break
            if status == DeviceStatus.RUNNING_RECOVERY_IMAGE:
                log("Device is already running the recovery image")
                return
            if status not in (DeviceStatus.STATUS_PENDING, DeviceStatus.DEVICE_HEALTHY):
                raise RecoveryError(f"device is not ready for recovery: {status.name}")
            self._check_deadline(
                startup_deadline, "timed out waiting for the device to enter recovery mode"
            )
            time.sleep(self.poll_interval)

        log("Device entered recovery mode")
        log("Initializing recovery control")
        self.transport.write(RecoveryCommand.RECOVERY_CTRL, bytes((0, 0, 0)))

        sent = [False, False, False]
        progress_deadline = time.monotonic() + self.state_timeout
        while True:
            self._check_deadline(
                progress_deadline, "timed out waiting for recovery state progress"
            )
            device_status = self._device_status()
            if device_status in (
                DeviceStatus.DEVICE_HEALTHY,
                DeviceStatus.RUNNING_RECOVERY_IMAGE,
            ):
                log("Recovery completed successfully")
                return
            if device_status not in (
                DeviceStatus.RECOVERY_MODE,
                DeviceStatus.RECOVERY_PENDING,
            ):
                raise RecoveryError(
                    f"recovery failed with device status {device_status.name}"
                )

            recovery_status, image_index = self._recovery_status()
            if recovery_status == DeviceRecoveryStatus.AWAITING_IMAGE:
                image = images.get(image_index)
                if sent[image_index]:
                    time.sleep(self.poll_interval)
                    continue
                log(
                    f"Sending image {image_index}: {images.name(image_index)} "
                    f"({len(image)} bytes)"
                )
                self._send_fifo_image(image)
                sent[image_index] = True
                log(f"Image {image_index} transferred; waiting for device processing")
                self._wait_for_recovery_pending()
                log(f"Activating image {image_index}")
                self.transport.write(
                    RecoveryCommand.RECOVERY_CTRL, bytes((self.cms, 0, 0x0F))
                )
                if all(sent):
                    log("All recovery images transferred and activated")
                    return
                progress_deadline = time.monotonic() + self.state_timeout
            elif recovery_status in (
                DeviceRecoveryStatus.BOOTING_IMAGE,
                DeviceRecoveryStatus.SUCCESS,
            ):
                time.sleep(self.poll_interval)
            else:
                raise RecoveryError(
                    f"device reported recovery failure {recovery_status.name}"
                )

    def probe(self) -> None:
        """Read OCP status registers without changing recovery state."""
        response = self._read_exact(RecoveryCommand.PROT_CAP, 15)
        if response[:8] != PROT_CAP_MAGIC:
            raise RecoveryError("invalid PROT_CAP magic")
        version = f"{response[8]}.{response[9]}"
        capabilities = int.from_bytes(response[10:12], "little")
        device_status = self._device_status()
        recovery_status, image_index = self._recovery_status()
        log(
            f"PROT_CAP magic={response[:8].decode('ascii')} "
            f"version={version} capabilities={capabilities:#06x}"
        )
        log(f"DEVICE_STATUS={device_status.name}")
        log(
            f"RECOVERY_STATUS={recovery_status.name} image_index={image_index}"
        )

    def _check_capabilities(self) -> None:
        response = self._read_exact(RecoveryCommand.PROT_CAP, 15)
        if response[:8] != PROT_CAP_MAGIC:
            raise RecoveryError("invalid PROT_CAP magic")
        capabilities = int.from_bytes(response[10:12], "little")
        if capabilities & (1 << 4) == 0:
            raise RecoveryError("DEVICE_STATUS is not supported")
        if capabilities & (1 << 12) == 0:
            raise RecoveryError("FIFO CMS is not supported")
        log("Device supports status reporting and FIFO CMS")

    def _device_status(self) -> DeviceStatus:
        response = self._read_exact(RecoveryCommand.DEVICE_STATUS, 7)
        try:
            return DeviceStatus(response[0])
        except ValueError as error:
            raise RecoveryError(f"invalid device status {response[0]:#04x}") from error

    def _recovery_status(self) -> tuple[DeviceRecoveryStatus, int]:
        response = self._read_exact(RecoveryCommand.RECOVERY_STATUS, 2)
        raw_status = response[0] & 0x0F
        try:
            status = DeviceRecoveryStatus(raw_status)
        except ValueError as error:
            raise RecoveryError(f"invalid recovery status {raw_status:#04x}") from error
        return status, response[0] >> 4

    def _wait_for_recovery_pending(self) -> None:
        deadline = time.monotonic() + self.state_timeout
        while self._device_status() != DeviceStatus.RECOVERY_PENDING:
            self._check_deadline(
                deadline, "timed out waiting for the device to process the recovery image"
            )
            time.sleep(self.poll_interval)

    def _send_fifo_image(self, image: bytes) -> None:
        padded_image = image + bytes((-len(image)) % 4)
        image_size_dwords = len(padded_image) // 4
        fifo_control = bytes((self.cms, 0)) + struct.pack("<I", image_size_dwords)
        self.transport.write(RecoveryCommand.INDIRECT_FIFO_CTRL, fifo_control)

        offset = 0
        deadline = time.monotonic() + self.state_timeout
        while offset < len(padded_image):
            status = self._fifo_status()
            available_dwords = status.available_dwords()
            if available_dwords == 0:
                self._check_deadline(deadline, "timed out waiting for FIFO space")
                time.sleep(self.poll_interval)
                continue
            max_bytes = min(status.max_transfer_dwords * 4, USB_CONTROL_MAX_BYTES)
            chunk_length = min(
                available_dwords * 4, max_bytes, len(padded_image) - offset
            )
            if chunk_length <= 0:
                raise RecoveryError("device reported an invalid FIFO transfer size")
            self.transport.write(
                RecoveryCommand.INDIRECT_FIFO_DATA,
                padded_image[offset : offset + chunk_length],
            )
            offset += chunk_length

    def _fifo_status(self) -> FifoStatus:
        response = self._read_exact(RecoveryCommand.INDIRECT_FIFO_STATUS, 20)
        return FifoStatus(
            full=bool(response[0] & 2),
            write_index=int.from_bytes(response[4:8], "little"),
            read_index=int.from_bytes(response[8:12], "little"),
            size_dwords=int.from_bytes(response[12:16], "little"),
            max_transfer_dwords=int.from_bytes(response[16:20], "little"),
        )

    def _read_exact(self, command: RecoveryCommand, length: int) -> bytes:
        response = self.transport.read(command, length)
        if len(response) != length:
            raise RecoveryError(
                f"invalid {command.name} response length {len(response)}; expected {length}"
            )
        return response

    @staticmethod
    def _check_deadline(deadline: float, message: str) -> None:
        if time.monotonic() >= deadline:
            raise RecoveryError(message)


def log(message: str) -> None:
    print(f"[usb-recovery] {message}", file=sys.stderr, flush=True)


def parse_usb_id(value: str) -> int:
    try:
        usb_id = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid USB ID: {value}") from error
    if not 0 <= usb_id <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return usb_id


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--caliptra-fmc-rt", type=Path)
    parser.add_argument("--soc-manifest", type=Path)
    parser.add_argument("--mcu-runtime", type=Path)
    parser.add_argument("--vendor-id", type=parse_usb_id, default=DEFAULT_VENDOR_ID)
    parser.add_argument("--product-id", type=parse_usb_id, default=DEFAULT_PRODUCT_ID)
    parser.add_argument("--discovery-timeout", type=float, default=10.0)
    parser.add_argument("--transfer-timeout", type=float, default=10.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    image_paths = (args.caliptra_fmc_rt, args.soc_manifest, args.mcu_runtime)
    if not args.probe and any(path is None for path in image_paths):
        parser.error(
            "--caliptra-fmc-rt, --soc-manifest, and --mcu-runtime are required "
            "unless --probe is used"
        )
    try:
        log(f"Opening USB device {args.vendor_id:04x}:{args.product_id:04x}")
        with PyUsbTransport.open(
            args.vendor_id,
            args.product_id,
            args.discovery_timeout,
            args.transfer_timeout,
        ) as transport:
            log("USB interface claimed")
            agent = RecoveryAgent(transport)
            if args.probe:
                agent.probe()
            else:
                log("Loading recovery images")
                images = RecoveryImages(
                    caliptra_fmc_rt=args.caliptra_fmc_rt.read_bytes(),
                    soc_manifest=args.soc_manifest.read_bytes(),
                    mcu_runtime=args.mcu_runtime.read_bytes(),
                )
                agent.run(images)
        log("Done")
        return 0
    except (OSError, RecoveryError, usb.core.USBError) as error:
        print(f"usb-recovery: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
