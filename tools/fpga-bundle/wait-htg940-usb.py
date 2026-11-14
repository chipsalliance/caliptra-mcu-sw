#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Wait for a claimable recovery interface that answers standard USB requests."""

import argparse
import time

import libusb_package
import usb.core
import usb.util


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    deadline = time.monotonic() + args.timeout
    last_error = "device not present"
    previous_error = None
    while time.monotonic() < deadline:
        device = None
        ready = False
        try:
            device = libusb_package.find(idVendor=0x0424, idProduct=0x0007)
            if device is not None:
                usb.util.claim_interface(device, 0)
                descriptor = device.ctrl_transfer(0x80, 6, 0x0100, 0, 18, timeout=500)
                ready = (
                    len(descriptor) == 18 and descriptor[0] == 18 and descriptor[1] == 1
                    and bytes(descriptor[8:12]) == bytes.fromhex("24040700")
                )
                if not ready:
                    last_error = "unexpected standard device descriptor"
            else:
                last_error = "device not present"
        except (usb.core.USBError, NotImplementedError) as error:
            last_error = str(error)
        finally:
            if device is not None:
                try:
                    usb.util.dispose_resources(device)
                except usb.core.USBError as error:
                    ready = False
                    last_error = f"device cleanup failed: {error}"
        if ready:
            print("USB_READY: 0424:0007 answers standard GET_DESCRIPTOR.", flush=True)
            return 0
        if last_error != previous_error:
            print(f"Waiting for USB interface: {last_error}", flush=True)
            previous_error = last_error
        time.sleep(0.1)
    print(f"USB readiness timed out after {args.timeout}s: {last_error}", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
