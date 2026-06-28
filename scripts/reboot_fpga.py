#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
Reboot an FPGA board over its serial console (/dev/ttyUSB3, 115200).

What the script does:
  1. Waits for a root shell prompt on the serial port.
  2. Installs openssh-server and net-tools.
  3. Creates user 'ubuntu' with password 'petalinux' and passwordless sudo.
  4. Provisions the local no_passwd_key.pub for passwordless SSH (for root
     and ubuntu).
  5. Retrieves the board's IP address and writes it to scripts/.env.
"""

import argparse
import os
import re
import sys
import time

import serial

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, ".env")

DEFAULT_PORT = "/dev/ttyUSB3"
DEFAULT_BAUD = 115200
DEFAULT_TIMEOUT = 5          # per-read timeout in seconds
COMMAND_DELAY = 0.5          # pause between sending commands
LONG_COMMAND_TIMEOUT = 120   # for apt-get installs

SSH_PUBKEY_PATH = os.path.expanduser("~/.ssh/no_passwd_key.pub")


def read_until_prompt(ser, prompt_re=r"(#|\\$)\s*$", timeout=None):
    """Read serial output until we see a shell prompt or timeout."""
    timeout = timeout or ser.timeout
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            buf += chunk.decode("utf-8", errors="replace")
            if re.search(prompt_re, buf):
                return buf
    return buf


def wait_for_string(ser, target="BEAM Tool Web", timeout=LONG_COMMAND_TIMEOUT):
    """Read serial output until the target string appears or timeout."""
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            buf += chunk.decode("utf-8", errors="replace")
            if target in buf:
                print(f"[+] Found '{target}' in output.")
                return buf
    print(f"[!] Timed out waiting for '{target}'.")
    return None


def send_cmd(ser, cmd, timeout=None, prompt_re=r"(#|\\$)\s*$"):
    """Send a command over serial, wait for prompt, return output."""
    timeout = timeout or DEFAULT_TIMEOUT
    # Flush any pending input
    ser.reset_input_buffer()
    ser.write((cmd + "\n").encode("utf-8"))
    time.sleep(COMMAND_DELAY)
    output = read_until_prompt(ser, prompt_re=prompt_re, timeout=timeout)
    return output


def wait_for_shell(ser, retries=5):
    """Press Enter a few times until we get a shell prompt.

    The Xilinx System Controller has a two-step console access:
      1. Send \\r\\n + tab to wake it up → it shows ':R' or similar prompt
      2. Send 'EXT' + tab (tab-completes to the exit/passthrough command) + \\r
         → drops into the Linux shell
    """
    for i in range(retries):
        print(f"[*] Waiting for shell prompt (attempt {i + 1}/{retries})...")
        # Flush any stale input
        ser.reset_input_buffer()

        # Step 1: Wake the system controller with Enter + Tab
        ser.write(b"\r")
        time.sleep(0.3)
        ser.write(b"\t")
        time.sleep(1)

        # Read whatever came back (looking for ':R' or a prompt)
        output = read_until_prompt(ser, timeout=3)
        print(f"    [dbg] after wake: {repr(output[-80:])}")

        # If we already have a Linux shell prompt, we're done
        if re.search(r"[#$]\s*$", output):
            print("[+] Got shell prompt.")
            return True

        # Step 2: Send EXT + Tab (for tab-completion) + Enter
        ser.write(b"EXT")
        time.sleep(0.2)
        ser.write(b"\t")
        time.sleep(0.5)
        ser.write(b"\r")
        time.sleep(2)

        # Read the response — should now be a Linux login or shell prompt
        output = read_until_prompt(ser, timeout=DEFAULT_TIMEOUT)
        print(f"    [dbg] after EXT: {repr(output[-80:])}")

        if re.search(r"[#$]\s*$", output):
            print("[+] Got shell prompt.")
            return True

        # Check if we hit a login prompt
        if re.search(r"login:", output, re.IGNORECASE):
            print("[*] Detected login prompt, attempting root login...")
            ser.write(b"root\r")
            time.sleep(2)
            output = read_until_prompt(ser, timeout=DEFAULT_TIMEOUT)
            if re.search(r"[#$]\s*$", output):
                print("[+] Logged in as root.")
                return True
    return False


def reboot(ser):
    """Reboot the board and wait for shell prompt."""
    print("[*] Rebooting the board...")
    output = send_cmd(ser, "reboot -n", timeout=LONG_COMMAND_TIMEOUT)
    print(output[-200:] if len(output) > 200 else output)



def main():
    parser = argparse.ArgumentParser(description="Setup FPGA board over serial console")
    parser.add_argument(
        "--port", default=DEFAULT_PORT, help=f"Serial port (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--baud", type=int, default=DEFAULT_BAUD, help=f"Baud rate (default: {DEFAULT_BAUD})"
    )
    args = parser.parse_args()


    print(f"[*] Opening serial port {args.port} @ {args.baud}...")
    ser = serial.Serial(args.port, args.baud, timeout=DEFAULT_TIMEOUT)

    try:
        if not wait_for_shell(ser):
            print("[!] Could not get a shell prompt. Is the board booted?", file=sys.stderr)
            sys.exit(1)
        reboot(ser)
        if wait_for_string(ser, target="BEAM Tool Web", timeout=LONG_COMMAND_TIMEOUT) is None:
            print("[!] Board did not boot to BEAM Tool Web. Check serial output.", file=sys.stderr)
            sys.exit(1)
        print("[+] Reboot complete...")
        print("Run 'scripts/setup_fpga.py' to re-setup the board.")

 
    finally:
        ser.close()


if __name__ == "__main__":
    main()
