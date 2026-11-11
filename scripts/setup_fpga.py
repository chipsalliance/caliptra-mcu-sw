#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
Setup an FPGA board over its serial console (/dev/ttyUSB1, 115200).

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

DEFAULT_PORT = "/dev/ttyUSB1"
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
    """Press Enter a few times until we get a shell prompt."""
    for i in range(retries):
        print(f"[*] Waiting for shell prompt (attempt {i + 1}/{retries})...")
        ser.write(b"\n")
        time.sleep(1)
        output = read_until_prompt(ser, timeout=DEFAULT_TIMEOUT)
        if re.search(r"(#|\$)\s*$", output):
            print("[+] Got shell prompt.")
            return True
        # Check if we hit a login prompt
        if re.search(r"login:", output, re.IGNORECASE):
            print("[*] Detected login prompt, attempting root login...")
            ser.write(b"root\n")
            time.sleep(2)
            output = read_until_prompt(ser, timeout=DEFAULT_TIMEOUT)
            if re.search(r"(#|\$)\s*$", output):
                print("[+] Logged in as root.")
                return True
    return False


def install_packages(ser):
    """Install openssh-server and net-tools."""
    print("[*] Updating package lists...")
    output = send_cmd(ser, "apt-get update -qy", timeout=LONG_COMMAND_TIMEOUT)
    print(output[-200:] if len(output) > 200 else output)

    print("[*] Installing openssh-server and net-tools...")
    output = send_cmd(
        ser,
        "DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server net-tools",
        timeout=LONG_COMMAND_TIMEOUT,
    )
    print(output[-200:] if len(output) > 200 else output)

    print("[*] Enabling and starting sshd...")
    send_cmd(ser, "systemctl enable ssh", timeout=30)
    send_cmd(ser, "systemctl start ssh", timeout=30)


def create_user(ser):
    """Create 'ubuntu' user with password 'petalinux' and passwordless sudo."""
    print("[*] Creating user 'ubuntu'...")
    # Create user if it doesn't exist; ignore error if it does
    send_cmd(ser, "id ubuntu 2>/dev/null || useradd -m -s /bin/bash ubuntu", timeout=10)
    # Set password
    send_cmd(ser, "echo 'ubuntu:petalinux' | chpasswd", timeout=10)
    # Add to sudo group and configure passwordless sudo
    send_cmd(ser, "usermod -aG sudo ubuntu", timeout=10)
    send_cmd(
        ser,
        "echo 'ubuntu ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ubuntu",
        timeout=10,
    )
    send_cmd(ser, "chmod 0440 /etc/sudoers.d/ubuntu", timeout=10)
    print("[+] User 'ubuntu' created with passwordless sudo.")


def provision_ssh_keys(ser, pubkey):
    """Install SSH public key for both root and ubuntu."""
    # Escape single quotes in key (shouldn't have any, but be safe)
    safe_key = pubkey.replace("'", "'\\''")

    for user, home in [("root", "/root"), ("ubuntu", "/home/ubuntu")]:
        print(f"[*] Provisioning SSH key for {user}...")
        send_cmd(ser, f"mkdir -p {home}/.ssh", timeout=10)
        send_cmd(ser, f"chmod 700 {home}/.ssh", timeout=10)
        # Append key if not already present
        send_cmd(
            ser,
            f"grep -qF '{safe_key}' {home}/.ssh/authorized_keys 2>/dev/null "
            f"|| echo '{safe_key}' >> {home}/.ssh/authorized_keys",
            timeout=10,
        )
        send_cmd(ser, f"chmod 600 {home}/.ssh/authorized_keys", timeout=10)
        send_cmd(ser, f"chown -R {user}:{user} {home}/.ssh", timeout=10)

    # Allow root login via key and ensure pubkey auth is on
    send_cmd(
        ser,
        "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
        timeout=10,
    )
    send_cmd(
        ser,
        "sed -i 's/^#\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
        timeout=10,
    )
    send_cmd(ser, "systemctl restart ssh", timeout=15)
    print("[+] SSH keys provisioned.")


def acquire_ip_address(ser):
    """Bring up network interfaces and obtain an IPv4 address via DHCP."""
    print("[*] Detecting network interfaces...")
    marker = "IFACE_START"
    marker_end = "IFACE_END"
    output = send_cmd(
        ser,
        f"echo {marker}; ls /sys/class/net/; echo {marker_end}",
        timeout=10,
    )
    # Extract text between markers (exact line match to avoid the echoed command)
    iface = None
    in_block = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == marker_end:
            break
        if in_block:
            for name in stripped.split():
                # Only pick Ethernet-like interfaces (eth*, en*, wl*, wlan*)
                if name and re.match(r"^(eth|en|wl)", name):
                    iface = name
                    break
            if iface:
                break
        if stripped == marker:
            in_block = True

    if not iface:
        print("[!] No network interface found.", file=sys.stderr)
        return None

    print(f"[*] Bringing up interface {iface}...")
    send_cmd(ser, f"ip link set {iface} up", timeout=10)
    time.sleep(2)

    # Try dhclient first, fall back to dhcpcd
    print(f"[*] Requesting IPv4 address via DHCP on {iface}...")
    output = send_cmd(ser, f"dhclient -4 -v {iface} 2>&1 || dhcpcd -4 {iface} 2>&1",
                      timeout=LONG_COMMAND_TIMEOUT)
    print(output[-300:] if len(output) > 300 else output)

    # Give the interface a moment to settle
    time.sleep(3)


def get_ip_address(ser):
    """Retrieve the board IP address via ifconfig."""
    output = send_cmd(ser, "ifconfig", timeout=10)
    # Look for inet addr on any non-loopback interface
    # Matches both "inet addr:x.x.x.x" and "inet x.x.x.x"
    matches = re.findall(r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", output)
    for ip in matches:
        if not ip.startswith("127."):
            return ip
    return None


def save_env(ip_address):
    """Write the FPGA IP address to scripts/.env."""
    with open(ENV_FILE, "w") as f:
        f.write(f"FPGA_IP={ip_address}\n")
    print(f"[+] Saved FPGA_IP={ip_address} to {ENV_FILE}")


def main():
    parser = argparse.ArgumentParser(description="Setup FPGA board over serial console")
    parser.add_argument(
        "--port", default=DEFAULT_PORT, help=f"Serial port (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--baud", type=int, default=DEFAULT_BAUD, help=f"Baud rate (default: {DEFAULT_BAUD})"
    )
    parser.add_argument(
        "--ssh-key",
        default=SSH_PUBKEY_PATH,
        help=f"Path to SSH public key (default: {SSH_PUBKEY_PATH})",
    )
    args = parser.parse_args()

    # Read SSH public key
    if not os.path.isfile(args.ssh_key):
        print(f"[!] SSH public key not found: {args.ssh_key}", file=sys.stderr)
        sys.exit(1)
    with open(args.ssh_key) as f:
        pubkey = f.read().strip()

    print(f"[*] Opening serial port {args.port} @ {args.baud}...")
    ser = serial.Serial(args.port, args.baud, timeout=DEFAULT_TIMEOUT)

    try:
        if not wait_for_shell(ser):
            print("[!] Could not get a shell prompt. Is the board booted?", file=sys.stderr)
            sys.exit(1)

        install_packages(ser)
        create_user(ser)
        provision_ssh_keys(ser, pubkey)
        acquire_ip_address(ser)

        ip = get_ip_address(ser)
        if ip:
            save_env(ip)
        else:
            print("[!] Could not determine IP address. Is a network cable connected?",
                  file=sys.stderr)
            sys.exit(1)

        print("[+] FPGA setup complete. You can now SSH with:")
        print(f"    ssh -i ~/.ssh/no_passwd_key ubuntu@{ip}")
        print(f"    ssh -i ~/.ssh/no_passwd_key root@{ip}")
    finally:
        ser.close()


if __name__ == "__main__":
    main()
