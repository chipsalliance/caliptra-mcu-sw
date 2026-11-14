#!/usr/bin/env python3
"""Separate board I/O/timing constraints from saved debug instrumentation."""
import argparse
import re
from pathlib import Path


DEBUG_COMMANDS = [
    re.compile(r"set_property\s+MARK_DEBUG\s+\S+\s+\[get_nets\s+.+\]"),
    re.compile(r"set_property\s+\S+\s+\S+\s+\[get_debug_(?:cores|ports)\s+.+\]"),
    re.compile(r"connect_debug_port\s+\S+\s+\[get_nets\s+.+\]"),
    re.compile(r"create_debug_(?:core|port)\s+\S+\s+\S+"),
]


def board_constraints(text: str) -> tuple[str, int]:
    kept = []
    removed = 0
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        command = line.strip()
        if not command or command.startswith("#"):
            kept.append(line)
        elif any(pattern.fullmatch(command) for pattern in DEBUG_COMMANDS):
            removed += 1
        elif re.search(r"\b(?:MARK_DEBUG|\w*debug_\w*)\b", command):
            raise ValueError(f"Unsupported debug constraint at line {number}: {command}")
        else:
            kept.append(line)
    return "".join(kept), removed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"Constraint output already exists: {args.output}")
    text, removed = board_constraints(args.source.read_text())
    args.output.mkdir(parents=True)
    (args.output / "htg940_board_io.xdc").write_text(text)
    (args.output / "dual_ila_debug.xdc").write_text("")
    print(f"HTG_DUAL_ILA_CONSTRAINTS: removed {removed} saved debug commands; "
          f"board I/O and timing retained in {args.output}")


if __name__ == "__main__":
    main()
