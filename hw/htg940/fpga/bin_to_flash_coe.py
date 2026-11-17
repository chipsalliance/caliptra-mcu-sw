#!/usr/bin/env python3
"""Convert flash_image.bin into a fixed-size 64-bit Xilinx COE image."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--capacity", required=True, type=int)
    args = parser.parse_args()

    data = args.input.read_bytes()
    if len(data) > args.capacity:
        raise SystemExit(
            f"{args.input}: {len(data)} bytes exceeds {args.capacity}-byte Slot A"
        )
    if args.capacity % 8:
        raise SystemExit("capacity must be divisible by 8")

    # Slot A is the first half.  The rest of the 2 MiB memory is erased (0xff),
    # including Slot B/staging and the service partitions.
    image = data + bytes([0xFF]) * (args.capacity - len(data))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="ascii", newline="\n") as output:
        output.write("memory_initialization_radix=16;\n")
        output.write("memory_initialization_vector=\n")
        for offset in range(0, len(image), 8):
            word = int.from_bytes(image[offset : offset + 8], "little")
            suffix = ";\n" if offset + 8 == len(image) else ",\n"
            output.write(f"{word:016x}{suffix}")

    print(
        f"{args.input} -> {args.output}: {len(data)} payload bytes, "
        f"{args.capacity} initialized bytes"
    )


if __name__ == "__main__":
    main()
