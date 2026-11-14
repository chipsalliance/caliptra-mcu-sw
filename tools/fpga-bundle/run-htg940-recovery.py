#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Own one Windows UART console and one USB recovery attempt, retaining logs."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

CONSOLE_READY = "[HOST] Monitoring MCU/Caliptra logs."
RUNTIME_READY = "[mcu-runtime] Hello from MCU runtime"


def stop_owned(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_for_line(
    log: Path,
    marker: str,
    console: subprocess.Popen[bytes],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in log.read_text(encoding="utf-8", errors="replace"):
            return
        if console.poll() is not None:
            raise RuntimeError(f"UART console exited with {console.returncode}; see {log}")
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for {marker!r}; see {log}")


def wait_for_process(
    process: subprocess.Popen[bytes],
    console: subprocess.Popen[bytes],
    timeout: float,
) -> int:
    deadline = time.monotonic() + timeout
    status = process.poll()
    while status is None:
        if console.poll() is not None:
            raise RuntimeError("UART console exited during USB discovery/recovery")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"USB operation exceeded {timeout}s")
        time.sleep(0.1)
        status = process.poll()
    return status


def run(args: argparse.Namespace) -> int:
    directory: Path = args.recovery_dir.resolve()
    console_script = directory / "htg940_console_updated.py"
    recovery_script = directory / "usb_recovery.py"
    for path in (console_script, recovery_script, directory / "entropy_host.py"):
        if not path.is_file():
            raise FileNotFoundError(path)
    if args.preflight:
        subprocess.run(
            [sys.executable, "-c",
             "import serial, usb.core; "
             "s = serial.Serial(__import__('sys').argv[1], 115200, timeout=1); s.close()",
             args.port],
            check=True,
        )
        print(f"Preflight passed: {args.port}, PySerial, and PyUSB", flush=True)
        return 0
    if args.log_prefix is None:
        raise ValueError("--log-prefix is required unless --preflight is selected")
    images = (args.caliptra_fmc_rt, args.soc_manifest, args.mcu_runtime)
    if any(path is None or not path.is_file() for path in images):
        raise ValueError("All three recovery images must exist")
    uart_log = Path(str(args.log_prefix) + ".uart.log")
    recovery_log = Path(str(args.log_prefix) + ".recovery.log")
    uart_log.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    print(f"UART log: {uart_log}\nRecovery log: {recovery_log}", flush=True)
    with uart_log.open("xb") as uart_output, recovery_log.open("xb") as recovery_output:
        console = subprocess.Popen(
            [sys.executable, "-u", str(console_script), "--port", args.port,
             "--restart-local", "monitor"],
            cwd=directory, env=env, stdout=uart_output, stderr=subprocess.STDOUT,
        )
        recovery = None
        try:
            wait_for_line(uart_log, CONSOLE_READY, console, args.startup_timeout)
            recovery = subprocess.Popen(
                [sys.executable, "-u", str(Path(__file__).with_name("wait-htg940-usb.py")),
                 "--timeout", str(args.usb_ready_timeout)],
                cwd=directory, env=env, stdout=recovery_output, stderr=subprocess.STDOUT,
            )
            if wait_for_process(recovery, console, args.usb_ready_timeout + 5) != 0:
                print(recovery_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
                raise RuntimeError("USB interface did not become ready; recovery was not started")
            recovery = subprocess.Popen(
                [sys.executable, "-u", str(recovery_script),
                 "--caliptra-fmc-rt", str(args.caliptra_fmc_rt),
                 "--soc-manifest", str(args.soc_manifest),
                 "--mcu-runtime", str(args.mcu_runtime),
                 "--vendor-id", "0x0424", "--product-id", "0x0007",
                 "--retries", "0", "--discovery-timeout", "15",
                 "--transfer-timeout", "5", "--state-timeout", str(args.state_timeout)],
                cwd=directory, env=env, stdout=recovery_output, stderr=subprocess.STDOUT,
            )
            wait_for_process(recovery, console, args.recovery_timeout)
            if recovery.returncode != 0:
                time.sleep(args.diagnostic_seconds)
                print(recovery_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
                print(f"USB recovery failed with {recovery.returncode}; target was not reset or retried.",
                      file=sys.stderr)
                return recovery.returncode if recovery.returncode > 0 else 1
            wait_for_line(uart_log, RUNTIME_READY, console, args.boot_timeout)
            print("HTG940_TEST_PASS: USB recovery completed and MCU runtime started.", flush=True)
            return 0
        finally:
            if recovery is not None:
                stop_owned(recovery)
            stop_owned(console)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovery-dir", type=Path, required=True)
    parser.add_argument("--port", default="COM8")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--caliptra-fmc-rt", type=Path)
    parser.add_argument("--soc-manifest", type=Path)
    parser.add_argument("--mcu-runtime", type=Path)
    parser.add_argument("--log-prefix", type=Path)
    parser.add_argument("--startup-timeout", type=float, default=90)
    parser.add_argument("--state-timeout", type=float, default=15)
    parser.add_argument("--usb-ready-timeout", type=float, default=30)
    parser.add_argument("--recovery-timeout", type=float, default=120)
    parser.add_argument("--boot-timeout", type=float, default=30)
    parser.add_argument("--diagnostic-seconds", type=float, default=2)
    args = parser.parse_args()
    for name in ("startup_timeout", "state_timeout", "usb_ready_timeout", "recovery_timeout", "boot_timeout"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.diagnostic_seconds < 0:
        parser.error("--diagnostic-seconds must not be negative")
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"HTG940_TEST_FAILED: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
