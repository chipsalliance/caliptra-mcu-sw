# VCK190 FPGA setup: SD card to running tests

This guide brings up a VCK190 for **Caliptra Subsystem / MCU testing** using
the Caliptra developer SD-card image and explicit commands. No additional
setup, build, deployment, or test helper scripts are required.
Build on an x86-64 Linux development host; run the resulting binaries on the
board's ARM Linux processor.

The commands below use the `subsystem` configuration and enable the
`hw-2-1` ROM feature: use a compatible hardware revision, firmware
checkout, and subsystem bitstream. Do not mix artifacts from different builds.
For other configurations, see [Working with an FPGA](./fpga.md).

## What gets installed or built?

| Artifact | Purpose | When to replace it |
|----------|---------|--------------------|
| SD-card disk image (`.img`) | ARM Linux, bootloader, kernel, and base FPGA configuration | Initial setup or a base-image/kernel change |
| Segmented bitstream (`caliptra-bitstream.pdi`) | Caliptra logic loaded into the already-booted FPGA | After board boot or a hardware change |
| Firmware bundle (`all-fw.zip`) | Caliptra Core and MCU ROMs, runtimes, manifests, and test firmware | After firmware changes |
| ARM test binaries (`caliptra-test-binaries.sqsh`) | Cross-compiled tests and nextest metadata | After test changes |
| ARM `xtask` executable | Runs FPGA commands on the board | After xtask/tooling changes |

**Flashing the SD card, loading the PDI, and loading firmware are different
operations.** You do not need to rewrite the SD card for each firmware change.
Vivado and PetaLinux are not needed for the prebuilt-image path below.

## 1. Gather the hardware and prepare the development host

You need:

- A VCK190 and its power supply.
- A microSD card large enough for the **uncompressed** disk image, and a card reader.
- A USB data cable for the board's J207 USB Type-C UART/JTAG connector.
- An Ethernet cable and a network providing DHCP and Internet/package access.
- An x86-64 Debian/Ubuntu development host with Internet access and sufficient
  disk space for Rust builds and FPGA test artifacts.

**Development host:**

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential gcc-aarch64-linux-gnu libclang-dev \
    squashfs-tools zstd rsync git curl ca-certificates pkg-config perl \
    openssh-client unzip picocom file
```

Install [rustup](https://rustup.rs/) if it is not already installed, then clone:

```bash
git clone --recursive https://github.com/chipsalliance/caliptra-mcu-sw.git
cd caliptra-mcu-sw
git submodule update --init --recursive
rustup show
rustup target add riscv32imc-unknown-none-elf aarch64-unknown-linux-gnu
```

For an existing checkout, use that checkout instead of cloning again.
`rustup show` selects the repository's pinned toolchain. Install nextest with
the separate toolchain recommended by the [FPGA prerequisites](./fpga.md#host-system):

```bash
rustup toolchain install 1.93 --profile minimal
cargo +1.93 install cargo-nextest --locked
cargo-nextest --version
```

The commands below build tests locally with `--no-container`, so Podman/Docker
is not required for this path.

Create a dedicated SSH key, **only if it does not already exist**:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/no_passwd_key
```

The examples use this filename; you can choose a different key if you update
the SSH configuration in step 4. For unattended operation, use an available
SSH agent or follow your lab's policy for passphrase-free keys.
Keep the private key on the development host. Only its `.pub` file is provisioned.

**Checkpoint:** `aarch64-linux-gnu-gcc --version`, `mksquashfs -version`,
`cargo-nextest --version`, and `rustup target list --installed` show the required
tools and both Rust targets.

## 2. Download and write the SD-card image

1. Open the Caliptra Core
   [Build FPGA SD image workflow](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml).
2. Select a successful run with the subsystem base image appropriate for your
   hardware/bitstream. Record the run URL or build identifier for reproducibility.
3. Download the **subsystem developer** artifact, named
   `caliptra-fpga-image-subsystem-dev` in the image workflow. You may need to
   sign in to GitHub to download artifacts.
4. Extract the downloaded ZIP. Use the disk image inside (for example,
   `dev-image.img`), **not the ZIP file**, as the flashing input.

Choose the `-dev` image, not the non-development CI image. The developer image
has a persistent writable root filesystem; the CI image uses an overlay and
is intended to be reflashed between jobs.

> **Compatibility:** `subsystem` and `core-on-subsystem` require a subsystem
> base image. A `core` base image is not interchangeable. A matching variant
> alone does not guarantee that an arbitrary PDI works with an older base image.

Write the image with a disk-imaging application, or use the following Linux
procedure.

**Development host, with the SD card in the card reader:**

```bash
lsblk -o NAME,PATH,SIZE,MODEL,TRAN,MOUNTPOINTS
```

Identify the SD card by model and capacity. Unmount each of its mounted
partitions before writing (for example, `sudo umount /dev/sdX1`).

> **Destructive operation:** the next command erases the entire selected disk.
> Replace `/dev/sdX` with the SD card's **whole-disk** device, not a partition
> such as `/dev/sdX1`. Do not select your host's system disk. No formatting or
> manual partition creation is needed.

```bash
sudo dd if=/absolute/path/to/dev-image.img of=/dev/sdX \
    bs=4M status=progress conv=fsync
sync
```

Wait for completion, safely eject the card, and remove it from the reader.
Keep the image/run identifier alongside your test records.

## 3. Connect the VCK190 and select SD boot

With the board powered **off**:

1. Insert the newly written OS card in the SD slot **on top of the board**.
   Leave the System Controller card in the slot underneath the board.
2. Set boot-mode switch **SW1[4:1] = OFF, OFF, OFF, ON** for SD1 boot. Check
   the switch numbering rather than assuming a left-to-right orientation;
   see the [boot-switch photo](../../hw/fpga/images/versal_boot_switch.jpg).
3. Connect J207 to the development host with the USB data cable.
4. Connect the processing-system Ethernet port to your DHCP-enabled network.
5. Connect power and turn the board on.

Find the processing-system (PS) UART on the development host:

```bash
ls -l /dev/serial/by-id/
ls -l /dev/ttyUSB*
```

The examples use `/dev/ttyUSB1`, but numbering can change when other USB serial
devices are attached. J207 exposes multiple interfaces: use the
**PS UART**, not JTAG, PL UART, or the System Controller UART.

If your account lacks serial-port permission, add it to the appropriate group
(`dialout` on Debian/Ubuntu) and log out and back in:

```bash
sudo usermod -aG dialout "$USER"
```

Open the console with **115200 baud, 8 data bits, no parity, 1 stop bit, no
flow control**:

```bash
picocom --baud 115200 --flow n /dev/ttyUSB1
```

Wait for Linux startup. The Caliptra developer-image startup script opens a
root console. Verify on the **board console**:

```bash
id -u
hostname
uname -m
cat /etc/caliptra-build-info
date
ip -4 addr
```

**Checkpoint:** UID is `0`, architecture is `aarch64`, hostname is
`caliptra-fpga`, and image metadata identifies the intended subsystem/dev image.
The FPGA tooling uses this hostname to recognize a Caliptra image; do not
rename it casually.

If the date is wrong, correct it before package installation or HTTPS access:

```bash
date -s 'YYYY-MM-DD HH:MM:SS'
```

Replace the placeholder with the actual current date/time. Do not perform a
full distribution/kernel upgrade.

## 4. Configure networking and SSH from the serial console

Keep the root serial console open for this step. Only one process should own
the serial port. These commands apply to the Debian-based Caliptra developer
image, not an arbitrary stock Ubuntu/PetaLinux installation.

### 4.1. Obtain the board's IP address

**Board serial console:**

```bash
ip -br link
ip -4 addr
ip route
cat /etc/resolv.conf
```

The developer image configures Ethernet for DHCP. Identify the connected
interface (usually `end0`) and record its non-loopback IPv4 address. If there is
no lease, check the cable and DHCP server. To request a lease manually on an
image with `dhclient` installed:

```bash
ip link set end0 up
dhclient -4 -v end0
ip -4 addr show dev end0
```

Replace `end0` if your interface name differs. If the image uses `dhcpcd`
instead, use `dhcpcd -4 end0` instead of `dhclient`; do not run competing DHCP
clients. Resolve networking/DNS problems before continuing with package installs.

### 4.2. Install and configure SSH

**Board serial console, as root:**

```bash
apt-get update
apt-get install -y openssh-server sudo rsync git make gcc
systemctl enable --now ssh
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-caliptra-lab.conf <<'EOF'
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
/usr/sbin/sshd -t
/usr/sbin/sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication) '
```

Confirm the effective configuration allows root login by public key and disables
password/keyboard-interactive authentication. The Debian SSH configuration
normally includes `/etc/ssh/sshd_config.d/*.conf`; if these settings do not take
effect, check the `Include` directive and earlier conflicting settings. Do not
close the serial session until SSH access is verified.

### 4.3. Authorize your host's public key

In a separate **development-host terminal**, display the public key:

```bash
cat ~/.ssh/no_passwd_key.pub
```

Copy the entire single line, starting with `ssh-ed25519`. On the **board serial
console**, replace the placeholder below with that line before executing:

```bash
install -d -m 0700 /root/.ssh
cat >> /root/.ssh/authorized_keys <<'EOF'
PASTE_THE_SINGLE_LINE_PUBLIC_KEY_HERE
EOF
chmod 0600 /root/.ssh/authorized_keys
chown root:root /root/.ssh /root/.ssh/authorized_keys
/usr/sbin/sshd -t
systemctl restart ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Record the displayed host-key fingerprint for the first SSH connection.
Only the **public** key is pasted onto the board; never copy your private key.
Repeat the authorization step only when adding a new key.

> **Lab access:** this workflow uses privileged root SSH access to load FPGA
> logic, mount test images, and run tests. Use an isolated/trusted lab network
> and follow your lab's access policy. No shared/default password is needed,
> and SSH host-key verification remains enabled.

### 4.4. Configure and verify SSH access

Create an SSH alias in the development host's `~/.ssh/config`, substituting the
actual IP address:

```sshconfig
Host vck190
    HostName <board-ipv4-address>
    User root
    IdentityFile ~/.ssh/no_passwd_key
    IdentitiesOnly yes
```

```bash
ssh vck190 'id; hostname; uname -m; sudo -n true'
```

Confirm the host-key fingerprint against the one displayed on the serial
console before accepting it. UID should be `0`, hostname `caliptra-fpga`, and
architecture `aarch64`. Update `HostName` if DHCP later changes the board address.
After SSH works, exit picocom with **Ctrl-A, Ctrl-X**.

### 4.5. Optional: create a non-root lab account

The remaining steps use `root` via the `vck190` alias, so this is optional.
To also provide the `ubuntu` account with key access on a fresh lab image,
run on the **board**:

```bash
id ubuntu
```

If that account does not exist, create it:

```bash
useradd -m -s /bin/bash ubuntu
```

Then configure its key and sudo access:

```bash
usermod -aG sudo ubuntu
install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
cat /root/.ssh/authorized_keys >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
chmod 0600 /home/ubuntu/.ssh/authorized_keys
printf '%s\n' 'ubuntu ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ubuntu
chmod 0440 /etc/sudoers.d/ubuntu
visudo -cf /etc/sudoers.d/ubuntu
```

Passwordless sudo grants full administrative access. Use it only if allowed by
your lab policy. Test the optional account from the development host with
`ssh -i ~/.ssh/no_passwd_key ubuntu@<board-ipv4-address>`.

## 5. Verify the board-side test tools

**Development host:**

```bash
ssh vck190
```

**Board SSH shell:**

```bash
cargo-nextest --version
sudo -n cargo-nextest --version
lsmod | grep io_module
ls -l /dev/uio0 /dev/uio1
test -e /sys/class/fpga_manager/fpga0/firmware
exit
```

The Caliptra image should supply a real ARM `cargo-nextest` executable and the
kernel module. Both the normal and sudo nextest commands must report a version,
not just print a stub message. Do not copy the host's x86-64 executable onto the
board.

If nextest is missing, cross-compile it on the **development host** using a
version compatible with the repository's nextest configuration (the image
builder uses `0.9.118`):

```bash
rustup target add --toolchain 1.93 aarch64-unknown-linux-gnu
cargo +1.93 install cargo-nextest --version 0.9.118 --locked \
    --target aarch64-unknown-linux-gnu \
    --root target/fpga-nextest
scp target/fpga-nextest/bin/cargo-nextest vck190:/tmp/cargo-nextest
ssh vck190 'install -m 0755 /tmp/cargo-nextest /usr/bin/cargo-nextest && sudo -n cargo-nextest --version'
```

Recheck the board tools after installation. As with other cross-compiled
executables, the host's ARM cross-toolchain must target a libc compatible with
the board image.

**Checkpoint:** root SSH access, nextest under sudo, the `io_module` driver,
UIO devices, and the FPGA-manager interface are available. If the driver or
devices are absent, investigate the image's serial/kernel logs before proceeding.

## 6. Build the PDI, firmware, and ARM test artifacts

Run the following subsections in order on the **development host**. Use Bash,
start from the repository root, and keep the same terminal open so the exported
variables remain set. Stop and resolve any command failure before continuing.
These commands do **not** rebuild the SD-card image.

### 6.1. Set output paths and cross-compilation variables

```bash
export REPO_ROOT="$PWD"
export ARTIFACTS_DIR="${REPO_ROOT}/target/fpga-artifacts"
export OPENSSL_CACHE_DIR="${HOME}/.cache/caliptra-fpga/openssl-3.5.2"
mkdir -p "${ARTIFACTS_DIR}"

export OPENSSL_NO_VENDOR=true
export OPENSSL_STATIC=true
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_CACHE_DIR}/native"
export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="${OPENSSL_CACHE_DIR}/arm"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
```

Repeat this subsection whenever you open a new build/deployment terminal.
It selects separate native and ARM OpenSSL libraries; the two are not
interchangeable.

### 6.2. Build static OpenSSL once for each architecture

Skip this subsection on later builds if both cached include/library sets are
already present. The separate source directories avoid mixing native and ARM
build outputs.

```bash
mkdir -p "${OPENSSL_CACHE_DIR}/native/src" "${OPENSSL_CACHE_DIR}/arm/src"
curl --fail --location \
    https://github.com/openssl/openssl/releases/download/openssl-3.5.2/openssl-3.5.2.tar.gz \
    --output "${OPENSSL_CACHE_DIR}/openssl.tar.gz"
printf '%s  %s\n' \
    c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec \
    "${OPENSSL_CACHE_DIR}/openssl.tar.gz" | sha256sum --check
```

**Do not extract or build if the checksum check fails.**

```bash
tar -xf "${OPENSSL_CACHE_DIR}/openssl.tar.gz" \
    -C "${OPENSSL_CACHE_DIR}/native/src" --strip-components=1
tar -xf "${OPENSSL_CACHE_DIR}/openssl.tar.gz" \
    -C "${OPENSSL_CACHE_DIR}/arm/src" --strip-components=1

(
    set -e
    cd "${OPENSSL_CACHE_DIR}/native/src"
    ./config no-shared no-apps no-quic
    make -j"$(nproc)" build_sw
)

(
    set -e
    cd "${OPENSSL_CACHE_DIR}/arm/src"
    ./config linux-aarch64 no-shared no-apps no-quic \
        --cross-compile-prefix=aarch64-linux-gnu-
    make -j"$(nproc)" build_sw
)

mkdir -p "${OPENSSL_CACHE_DIR}/native/lib" "${OPENSSL_CACHE_DIR}/arm/lib"
cp -a "${OPENSSL_CACHE_DIR}/native/src/include" "${OPENSSL_CACHE_DIR}/native/"
cp -a "${OPENSSL_CACHE_DIR}/arm/src/include" "${OPENSSL_CACHE_DIR}/arm/"
cp "${OPENSSL_CACHE_DIR}/native/src/libcrypto.a" \
    "${OPENSSL_CACHE_DIR}/native/src/libssl.a" "${OPENSSL_CACHE_DIR}/native/lib/"
cp "${OPENSSL_CACHE_DIR}/arm/src/libcrypto.a" \
    "${OPENSSL_CACHE_DIR}/arm/src/libssl.a" "${OPENSSL_CACHE_DIR}/arm/lib/"
```

Verify the two installations before continuing:

```bash
test -s "${X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/include/openssl/ssl.h" &&
test -s "${X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/lib/libcrypto.a" &&
test -s "${X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/lib/libssl.a" &&
test -s "${AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/include/openssl/ssl.h" &&
test -s "${AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/lib/libcrypto.a" &&
test -s "${AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR}/lib/libssl.a" &&
echo 'Native and ARM OpenSSL caches are ready'
```

### 6.3. Download the subsystem PDI

```bash
cd "${REPO_ROOT}"
cargo xtask-fpga fpga download-bitstream --configuration subsystem
cp caliptra-bitstream.pdi "${ARTIFACTS_DIR}/caliptra-bitstream.pdi"
```

The downloader uses the URL and hash in the
[bitstream manifest](../../hw/fpga/bitstream_manifests/subsystem.toml).
Retain this PDI for bootstrap after subsequent board boots.

### 6.4. Build firmware and the release-profile runtime

```bash
cd "${REPO_ROOT}"
cargo xtask-fpga fpga build \
    --configuration subsystem \
    --rom-features core_test,hw-2-1 \
    --mcu_cfg mcu,0x0,0xB00C0000,2,2,2,test-fpga-flash-ctrl \
    --separate-runtimes

cargo xtask runtime-build --platform fpga --profile release
cp all-fw.zip "${ARTIFACTS_DIR}/all-fw.zip"
```

The explicit test ROM features, flash-controller configuration, separate
runtimes, and extra release-profile build match the local test-artifact flow.
Keep them when reproducing that flow rather than building only a generic MCU
runtime.

### 6.5. Cross-compile the tests and board-side xtask

```bash
cd "${REPO_ROOT}"
cargo xtask-fpga fpga build-test --configuration subsystem --no-container
cargo build --package caliptra-mcu-xtask --features=fpga_realtime \
    --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/debug/caliptra-mcu-xtask \
    "${ARTIFACTS_DIR}/xtask"
cp caliptra-test-binaries.tar.zst "${ARTIFACTS_DIR}/caliptra-test-binaries.tar.zst"
```

Always run the Cargo commands after test/tooling changes. Cargo handles
incremental rebuilding; there is no separate helper-script cache to invalidate.

### 6.6. Package tests as a squashfs image

Use a fresh staging directory each time so deleted/renamed tests cannot linger
from an earlier extraction:

```bash
TEST_STAGING_DIR=$(mktemp -d "${ARTIFACTS_DIR}/test-staging.XXXXXX")
tar -xf "${ARTIFACTS_DIR}/caliptra-test-binaries.tar.zst" -C "${TEST_STAGING_DIR}"
mksquashfs "${TEST_STAGING_DIR}" \
    "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" -comp gzip -noappend
```

After successful packaging, the generated `test-staging.*` directory can be
removed; it is not deployed. `-noappend` replaces the output image rather than
adding to a stale image.

Check the output:

```bash
ls -lh "${ARTIFACTS_DIR}"
file "${ARTIFACTS_DIR}/xtask"
```

Expected files in `target/fpga-artifacts/`:

| File | Description |
|------|-------------|
| `caliptra-bitstream.pdi` | Downloaded FPGA logic |
| `all-fw.zip` | Firmware/test-firmware bundle |
| `xtask` | ARM Linux executable; `file` should identify AArch64 |
| `caliptra-test-binaries.sqsh` | Mountable test image |
| `caliptra-test-binaries.tar.zst` | Original nextest archive |

## 7. Deploy artifacts and bootstrap the FPGA

Ensure no other developer or test process is using the board. Deployment can
replace a mounted test image and reload FPGA logic.

**Development host**, with `REPO_ROOT` and `ARTIFACTS_DIR` set as in step 6.1:

```bash
ssh vck190 'bash -se' <<'EOF'
if mountpoint -q /tmp/caliptra-test-binaries; then
    umount /tmp/caliptra-test-binaries
fi
mkdir -p /tmp/caliptra-binaries /tmp/caliptra-test-binaries
EOF

scp "${ARTIFACTS_DIR}/xtask" "${ARTIFACTS_DIR}/all-fw.zip" \
    vck190:/tmp/caliptra-binaries/
scp "${ARTIFACTS_DIR}/caliptra-test-binaries.sqsh" vck190:/tmp/

ssh vck190 'bash -se' <<'EOF'
chmod 0755 /tmp/caliptra-binaries/xtask
mount -t squashfs -o loop /tmp/caliptra-test-binaries.sqsh /tmp/caliptra-test-binaries
EOF

cd "${REPO_ROOT}"
cargo xtask-fpga fpga bootstrap \
    --target-host vck190 \
    --configuration subsystem \
    --bitstream "${ARTIFACTS_DIR}/caliptra-bitstream.pdi"
```

Unmount the previous image **before** overwriting its backing file. If unmount
fails because it is busy, stop the test/reader using it; do not continue copying
over the mounted image.

The bootstrap command copies the local PDI, installs it at
`/lib/firmware/caliptra-bitstream.pdi`, and loads it through
`/sys/class/fpga_manager/fpga0/firmware`. It also prepares the board checkout
and records `subsystem` in `/dev/shm/fpga-config`. Copying firmware and mounting
the tests alone do not perform bootstrap. The local PDI stays in the artifacts
directory for reuse; no second manual bitstream load is needed.

Bootstrap creates a board-side `caliptra-mcu-sw` checkout if needed, but does
not synchronize an existing checkout to your development branch. Before testing,
make sure `/root/caliptra-mcu-sw` matches the source revision used for the build,
especially `.config/nextest.toml`. On a fresh, clean board checkout, a committed
revision available from `origin` can be selected with:

```bash
COMMIT=$(git rev-parse HEAD)
ssh vck190 "cd /root/caliptra-mcu-sw && \
    git fetch origin '${COMMIT}' && git checkout --detach '${COMMIT}'"
```

For local-only source/configuration changes, transfer the corresponding files
too. For example, copy the exact nextest configuration used by the build:

```bash
scp .config/nextest.toml vck190:/root/caliptra-mcu-sw/.config/nextest.toml
```

Do not overwrite another developer's board checkout.

Verify deployment:

```bash
ssh vck190 '
    cat /dev/shm/fpga-config &&
    test -x /tmp/caliptra-binaries/xtask &&
    test -s /tmp/caliptra-binaries/all-fw.zip &&
    test -s /lib/firmware/caliptra-bitstream.pdi &&
    test -s /tmp/caliptra-test-binaries/target/nextest/cargo-metadata.json &&
    test -s /tmp/caliptra-test-binaries/target/nextest/binaries-metadata.json &&
    findmnt /tmp/caliptra-test-binaries
'
```

**Checkpoint:** the marker says `subsystem`, all checks succeed, and the test
directory is a squashfs mount. The firmware and test locations are:

```text
/tmp/caliptra-binaries/xtask
/tmp/caliptra-binaries/all-fw.zip
/tmp/caliptra-test-binaries/target/...
/lib/firmware/caliptra-bitstream.pdi
```

## 8. Discover tests, then run one test

List tests explicitly before running them. This avoids mistaking a listing
fallback or an empty filter for successful validation.

**Development host:**

```bash
ssh vck190
```

**Board SSH shell:**

```bash
cd /root/caliptra-mcu-sw
export TEST_BIN=/tmp/caliptra-test-binaries
export CPTRA_TEST_WORKSPACE=/root/caliptra-mcu-sw
export CPTRA_FIRMWARE_BUNDLE=/tmp/caliptra-binaries/all-fw.zip
export RUST_BACKTRACE=1

cargo-nextest nextest list \
    --cargo-metadata="${TEST_BIN}/target/nextest/cargo-metadata.json" \
    --binaries-metadata="${TEST_BIN}/target/nextest/binaries-metadata.json" \
    --target-dir-remap="${TEST_BIN}/target" \
    --workspace-remap=. \
    --profile=nightly-ci

/tmp/caliptra-binaries/xtask fpga test \
    --test-filter 'package(caliptra-mcu-tests-integration) and test(test_i3c_simple)'
```

Confirm that the intended test is discovered and actually runs to completion.
The filter is a [nextest filterset](https://nexte.st/docs/filtersets/).
Explicitly filtered runs use the `nightly` profile; unfiltered subsystem runs
use `nightly-ci`, whose default filter selects the FPGA CI test set. An
unfiltered run is therefore **not every test in the repository**.

Run the configured suite:

```bash
/tmp/caliptra-binaries/xtask fpga test
exit
```

Alternatively, run a test directly over SSH from the **development host**,
setting the board-side environment explicitly:

```bash
ssh vck190 'bash -se' <<'EOF'
cd /root/caliptra-mcu-sw
export TEST_BIN=/tmp/caliptra-test-binaries
export CPTRA_TEST_WORKSPACE=/root/caliptra-mcu-sw
export CPTRA_FIRMWARE_BUNDLE=/tmp/caliptra-binaries/all-fw.zip
export RUST_BACKTRACE=1
/tmp/caliptra-binaries/xtask fpga test \
    --test-filter 'package(caliptra-mcu-tests-integration) and test(test_i3c_simple)'
EOF
```

Omit `--test-filter` and its argument to run the configured subsystem suite.
Do not launch parallel test sessions against the same board.

### Collect results, including on failure

Nextest writes `/tmp/junit.xml` on the board. Collect it from the development
host even if a test command failed:

```bash
mkdir -p target/fpga-test-results
scp vck190:/tmp/junit.xml target/fpga-test-results/junit.xml
```

Run the collection command separately even when the SSH/test command returns
nonzero. An absent report after an early error is not a passing result. Check
exit status, executed-test count, failures, skips, and the console log.

## 9. Run a firmware bundle directly (optional)

To boot firmware without the nextest harness, use the deployed ARM `xtask` on
the board after bootstrap:

**Board SSH shell:**

```bash
cd /root
/tmp/caliptra-binaries/xtask fpga-run \
    --zip /tmp/caliptra-binaries/all-fw.zip
```

`fpga-run` is the direct-run command, not `fpga test`. It executes locally on
the board and does not support `--target-host`. This flow is less exercised than
the FPGA test workflow; observe the boot/UART output and use the integration
tests for repeatable pass/fail validation. See
[Running on FPGA](./fpga.md#running-on-fpga) for individual firmware inputs and
additional options.

## 10. Repeat after edits or a board reboot

| Change | Required action |
|--------|-----------------|
| Firmware only | Repeat step 6.4 and copy the new `all-fw.zip`; no SD-card rewrite |
| Tests changed | Repeat steps 6.5 and 6.6, then unmount/copy/remount as in step 7 |
| xtask changed | Repeat step 6.5 and copy the new ARM `xtask` |
| Hardware/PDI changed | Obtain a compatible PDI/base image and repeat bootstrap in step 7 |
| Board reboot/power cycle | Check IP/SSH, redeploy temporary artifacts, and bootstrap again |

Restore step 6.1's environment in any new development-host terminal. For a
**firmware-only** change, rebuild with the same test configuration:

```bash
cd "${REPO_ROOT}"
cargo xtask-fpga fpga build \
    --configuration subsystem \
    --rom-features core_test,hw-2-1 \
    --mcu_cfg mcu,0x0,0xB00C0000,2,2,2,test-fpga-flash-ctrl \
    --separate-runtimes
cargo xtask runtime-build --platform fpga --profile release
cp all-fw.zip "${ARTIFACTS_DIR}/all-fw.zip"
scp "${ARTIFACTS_DIR}/all-fw.zip" vck190:/tmp/caliptra-binaries/
```

Then rerun step 8's test command. No bootstrap is needed if the board and PDI
have not changed.

For **xtask-only** changes:

```bash
cd "${REPO_ROOT}"
cargo build --package caliptra-mcu-xtask --features=fpga_realtime \
    --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/debug/caliptra-mcu-xtask \
    "${ARTIFACTS_DIR}/xtask"
scp "${ARTIFACTS_DIR}/xtask" vck190:/tmp/caliptra-binaries/
ssh vck190 'chmod 0755 /tmp/caliptra-binaries/xtask'
```

Do not replace an executable while a test session is using it. For **test
changes**, repeat the explicit compile/package/deploy commands in steps 6.5,
6.6, and 7; always package from a fresh staging directory.

After a board reboot, treat `/tmp` artifacts/mounts and `/dev/shm/fpga-config`
as lost. Recheck the board IP, update the SSH alias if needed, then repeat
step 7 and the verification/test steps using the existing host artifacts.
You normally do not need to repeat user/key provisioning on the persistent
developer image.
If you reflashed the SD card, repeat provisioning too.

## Troubleshooting

| Symptom | Check or recovery |
|---------|-------------------|
| No UART output | Confirm J207, a USB data cable, PS UART selection, permissions, 115200 8N1/no flow control, SD slot, and SW1 setting. |
| Serial console inaccessible | Close other serial tools and check device selection/permissions; only one process should own the PS UART. |
| Package/Git/HTTPS errors | Correct the board clock, then check Ethernet/DHCP, default route, DNS, and repository access. Do not use a distribution upgrade as a fix. |
| SSH permission denied | Verify IP, the `no_passwd_key` identity, root authorization, key-file permissions, and `sshd -T` settings. |
| `Exec format error` | `xtask` or nextest was built for the host rather than ARM64. Check with `file`. |
| `GLIBC_* not found` | The cross-build's libc requirements exceed the board image. Use a matching builder/sysroot or the container-based flow in the main FPGA guide. |
| FPGA is not bootstrapped | Run step 7's explicit bootstrap and check `/dev/shm/fpga-config`. Copying/loading a PDI alone does not create the marker. |
| Need to reload the PDI | Repeat the host-side bootstrap with the retained local PDI as shown in step 7. The installed board copy is under `/lib/firmware`. |
| Missing UIO devices or FPGA manager | Check the base image, loaded driver, and serial/kernel logs. Do not assume a generic Ubuntu image has the required FPGA support. |
| Missing/stale tests or unknown nextest profile | Recompile/repackage tests, check the squashfs mount, and synchronize the board checkout/config with the build source. |
| Wrapper-register access hangs | Stop tests, shut Linux down cleanly, then toggle board power. Check base-image/PDI compatibility and bootstrap again before MMIO access. |
| No local JUnit file after failure | Copy `/tmp/junit.xml` manually; inspect console logs if nextest never started. |

For hardware bring-up, the wrapper's magic register at `0xA4010000` should
contain `0x52545043`, and its version register at `0xA4010004` identifies the
FPGA RTL build (not your firmware checkout). Only read MMIO after confirming
that compatible logic is loaded; accesses to absent logic can hang the board.

## Alternative: stock Ubuntu or building FPGA hardware yourself

The prebuilt Caliptra developer image is the recommended path above.
A stock Ubuntu image is not a drop-in replacement: it may require a custom
`BOOT.BIN`, device-tree/kernel integration, and the FPGA kernel module.
The networking/SSH commands above do not perform those steps.

If you need to build the FPGA design or prepare a custom boot image, follow
the [hardware FPGA README](../../hw/fpga/README.md#fpga-build-steps).
Vivado and PetaLinux versions must match. That README also explains the
`boot1900.bin`/fallback boot-image procedure and why a clean shutdown plus
power toggle may be necessary instead of `reboot`.

Do not apply the Ubuntu `ubuntu`/`ubuntu` initial-login instructions to the
Caliptra developer image; their console/login behavior is different.
