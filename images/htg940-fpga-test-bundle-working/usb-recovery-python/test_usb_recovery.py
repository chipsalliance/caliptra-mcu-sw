# Licensed under the Apache-2.0 license

import collections
import struct
import unittest

from usb_recovery import (
    DeviceStatus,
    FifoStatus,
    PyUsbTransport,
    RecoveryAgent,
    RecoveryCommand,
    RecoveryImages,
)


class FakeUsbDevice:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.transfer: tuple[object, ...] | None = None

    def ctrl_transfer(self, *args: object, **kwargs: object) -> bytes:
        self.transfer = args
        return self.response


def prot_cap() -> bytes:
    response = bytearray(15)
    response[:8] = b"OCP RECV"
    response[10:12] = ((1 << 4) | (1 << 12)).to_bytes(2, "little")
    return bytes(response)


def fifo_status() -> bytes:
    response = bytearray(20)
    response[12:16] = (64).to_bytes(4, "little")
    response[16:20] = (64).to_bytes(4, "little")
    return bytes(response)


class MockTransport:
    def __init__(self, reads: list[tuple[RecoveryCommand, bytes]]) -> None:
        self.reads = collections.deque(reads)
        self.writes: list[tuple[RecoveryCommand, bytes]] = []

    def read(self, command: RecoveryCommand, length: int) -> bytes:
        expected_command, response = self.reads.popleft()
        assert command == expected_command
        assert length == len(response)
        return response

    def write(self, command: RecoveryCommand, data: bytes) -> None:
        self.writes.append((command, data))


class RecoveryAgentTests(unittest.TestCase):
    def test_usb_reads_request_advertised_maximum_length(self) -> None:
        device = FakeUsbDevice(prot_cap())
        transport = PyUsbTransport(device, 1000)

        response = transport.read(RecoveryCommand.PROT_CAP, len(prot_cap()))

        self.assertEqual(response, prot_cap())
        self.assertIsNotNone(device.transfer)
        self.assertEqual(device.transfer[4], 64)

    def test_probe_reads_status_without_writes(self) -> None:
        transport = MockTransport(
            [
                (RecoveryCommand.PROT_CAP, prot_cap()),
                (
                    RecoveryCommand.DEVICE_STATUS,
                    bytes((DeviceStatus.STATUS_PENDING, 0, 0, 0, 0, 0, 0)),
                ),
                (RecoveryCommand.RECOVERY_STATUS, bytes((0, 0))),
            ]
        )

        RecoveryAgent(transport).probe()

        self.assertEqual(transport.writes, [])

    def test_sends_requested_images_in_fifo_chunks(self) -> None:
        reads = [
            (RecoveryCommand.PROT_CAP, prot_cap()),
            (RecoveryCommand.DEVICE_STATUS, bytes((DeviceStatus.RECOVERY_MODE, 0, 0, 0, 0, 0, 0))),
        ]
        for index in range(3):
            reads.extend(
                [
                    (RecoveryCommand.DEVICE_STATUS, bytes((DeviceStatus.RECOVERY_MODE, 0, 0, 0, 0, 0, 0))),
                    (RecoveryCommand.RECOVERY_STATUS, bytes(((index << 4) | 1, 0))),
                    (RecoveryCommand.INDIRECT_FIFO_STATUS, fifo_status()),
                ]
            )
            if index == 0:
                reads.append((RecoveryCommand.INDIRECT_FIFO_STATUS, fifo_status()))
            reads.append(
                (RecoveryCommand.DEVICE_STATUS, bytes((DeviceStatus.RECOVERY_PENDING, 0, 0, 0, 0, 0, 0)))
            )

        transport = MockTransport(reads)
        agent = RecoveryAgent(transport, poll_interval=0, state_timeout=1)
        agent.run(
            RecoveryImages(
                caliptra_fmc_rt=bytes((0x11,)) * 68,
                soc_manifest=bytes((0x22,)) * 4,
                mcu_runtime=bytes((0x33,)) * 3,
            )
        )

        fifo_writes = [
            data
            for command, data in transport.writes
            if command == RecoveryCommand.INDIRECT_FIFO_DATA
        ]
        self.assertEqual([len(data) for data in fifo_writes], [64, 4, 4, 4])
        self.assertEqual(fifo_writes[-1], bytes((0x33, 0x33, 0x33, 0)))
        fifo_controls = [
            data
            for command, data in transport.writes
            if command == RecoveryCommand.INDIRECT_FIFO_CTRL
        ]
        self.assertEqual(fifo_controls[0], bytes((0, 0)) + struct.pack("<I", 17))
        activations = [
            data
            for command, data in transport.writes
            if command == RecoveryCommand.RECOVERY_CTRL and data == bytes((0, 0, 0x0F))
        ]
        self.assertEqual(len(activations), 3)

    def test_fifo_available_dwords_wraps_indices(self) -> None:
        status = FifoStatus(
            full=False,
            write_index=4,
            read_index=60,
            size_dwords=64,
            max_transfer_dwords=16,
        )
        self.assertEqual(status.available_dwords(), 56)


if __name__ == "__main__":
    unittest.main()
