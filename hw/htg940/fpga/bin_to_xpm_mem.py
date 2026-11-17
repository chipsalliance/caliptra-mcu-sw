#!/usr/bin/env python3
"""Convert a raw little-endian ROM binary to a 64-bit XPM .mem file."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--size", required=True, type=int, help="Expected byte count")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data = args.input.read_bytes()

    if len(data) != args.size:
        raise SystemExit(
            f"{args.input}: expected {args.size} bytes, got {len(data)}"
        )
    if len(data) % 8:
        raise SystemExit(f"{args.input}: size is not divisible by 8 bytes")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="ascii", newline="\n") as output:
        for offset in range(0, len(data), 8):
            word = int.from_bytes(data[offset : offset + 8], byteorder="little")
            output.write(f"{word:016x}\n")

    print(f"{args.input} -> {args.output}: {len(data) // 8} 64-bit words")


if __name__ == "__main__":
    main()
