#!/usr/bin/env python3
"""Check or apply the pinned HTG940 submodule patches without network access."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def git(path, *args):
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def patch_check(path, patch, reverse=False):
    args = ["git", "-C", str(path), "apply", "--check"]
    if reverse:
        args.append("--reverse")
    result = subprocess.run(args + [str(patch)], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip())
    return result.returncode == 0, result.stderr.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    config_dir = Path(__file__).resolve().parent
    root = config_dir.parents[1]
    pins = json.loads((config_dir / "submodule_pins.json").read_text())
    for pin in pins:
        path = root / pin["path"]
        if not (path / ".git").exists():
            raise RuntimeError(
                f"Uninitialized submodule: {pin['path']}. "
                "Prepare a fresh tree with bash hw/htg940/prepare_sources.sh, "
                "or initialize nested submodules in the HTG caliptra-ss checkout."
            )
        actual = git(path, "rev-parse", "HEAD")
        if actual != pin["commit"]:
            if args.check:
                raise RuntimeError(
                    f"{pin['path']}: expected {pin['commit']}, found {actual}"
                )
            if git(path, "status", "--porcelain", "--ignore-submodules=all"):
                raise RuntimeError(f"Refusing to change a dirty submodule: {pin['path']}")
            available = subprocess.run(
                ["git", "-C", str(path), "cat-file", "-e", pin["commit"] + "^{commit}"],
                capture_output=True, text=True,
            )
            if available.returncode:
                raise RuntimeError(
                    f"Missing commit {pin['commit']} in {pin['path']}. "
                    f"Fetch it explicitly with: git -C {path} fetch origin {pin['commit']}"
                )
            git(path, "checkout", "--detach", pin["commit"])
        if "patch" in pin:
            patch = config_dir / "submodule_patches" / pin["patch"]
            if hashlib.sha256(patch.read_bytes()).hexdigest() != pin["patch_sha256"]:
                raise RuntimeError(f"Patch checksum mismatch: {patch}")
            applied, _ = patch_check(path, patch, reverse=True)
            if not applied:
                if args.check:
                    raise RuntimeError(f"Required patch not applied: {pin['path']}")
                applicable, error = patch_check(path, patch)
                if not applicable:
                    raise RuntimeError(f"Patch conflicts in {pin['path']}:\n{error}")
                git(path, "apply", str(patch))
                applied, error = patch_check(path, patch, reverse=True)
                if not applied:
                    raise RuntimeError(f"Patch verification failed in {pin['path']}:\n{error}")
        print(f"PASS: {pin['path']} @ {pin['commit']}")
    print("HTG940_SOURCES_READY: all pinned submodules and required patches verified")


if __name__ == "__main__":
    main()
