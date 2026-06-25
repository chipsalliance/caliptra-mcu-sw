# FPGA Testing Scripts

Utility scripts for setting up and testing on the FPGA board.

## Prerequisites

```bash
# Install system dependencies
sudo apt-get install -y gcc-aarch64-linux-gnu squashfs-tools

# Install Rust targets
rustup target add riscv32imc-unknown-none-elf aarch64-unknown-linux-gnu

# Set up Python virtual environment (for setup_fpga.py)
cd scripts
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Scripts

### `setup_fpga.py` — Initial FPGA Board Setup

Connects to the FPGA board over serial (`/dev/ttyUSB1`, 115200 baud) and:
- Installs `openssh-server` and `net-tools`
- Creates user `ubuntu` with password `petalinux` and passwordless sudo
- Provisions `~/.ssh/no_passwd_key.pub` for passwordless SSH (root + ubuntu)
- Brings up the network interface and obtains an IPv4 address via DHCP
- Saves the IP to `scripts/.env` as `FPGA_IP=<address>`

```bash
# Default serial port and SSH key
python setup_fpga.py

# Custom serial port
python setup_fpga.py --port /dev/ttyUSB2

# Custom SSH key
python setup_fpga.py --ssh-key ~/.ssh/id_ed25519.pub
```

After running, you can SSH into the board:
```bash
ssh -i ~/.ssh/no_passwd_key ubuntu@<FPGA_IP>
ssh -i ~/.ssh/no_passwd_key root@<FPGA_IP>
```

### `build_fpga_artifacts.sh` — Build & Deploy Test Artifacts

Mirrors the `build_test_binaries` CI job from `.github/workflows/fpga.yml` for local development. Builds all artifacts into `scripts/fpga-artifacts/` and optionally deploys them to the FPGA board via SCP.

**Build only:**
```bash
./build_fpga_artifacts.sh
```

**Build and deploy to FPGA:**
```bash
./build_fpga_artifacts.sh --deploy
```

**Deploy previously built artifacts (skip build):**
```bash
./build_fpga_artifacts.sh --deploy-only
```

**First-time setup (build OpenSSL from source):**
```bash
./build_fpga_artifacts.sh --build-openssl --with-bitstream --deploy
```

**Skip re-downloading the bitstream:**
```bash
./build_fpga_artifacts.sh --with-bitstream
```

**All options:**
| Flag | Description |
|------|-------------|
| `--deploy` | Build artifacts and deploy to FPGA board |
| `--deploy-only` | Skip build, deploy existing artifacts |
| `--build-openssl` | Build OpenSSL for native and ARM (cached in `/tmp/openssl`) |
| `--configuration <mode>` | FPGA configuration mode (default: `subsystem`) |
| `--with-bitstream` | Download FPGA bitstream (skipped by default) |

### `run_fpga_tests.sh` — Run Tests on the FPGA Board

SSHes into the FPGA board and runs the test suite via `xtask fpga test`. Fetches `junit.xml` results back to `scripts/fpga-test-results/`.

**Run all tests:**
```bash
./run_fpga_tests.sh
```

**Load bitstream first, then run tests:**
```bash
./run_fpga_tests.sh --bootstrap
```

**Run a specific test by name:**
```bash
./run_fpga_tests.sh --filter "test_name"
```

**List available tests:**
```bash
./run_fpga_tests.sh --list
```

**All options:**
| Flag | Description |
|------|-------------|
| `--bootstrap` | Load bitstream before running tests |
| `--filter <pattern>` | Run only tests matching the pattern |
| `--list` | List available tests without running them |

## Generated Files (gitignored)

| Path | Description |
|------|-------------|
| `scripts/.env` | Contains `FPGA_IP=<address>` after setup |
| `scripts/.venv/` | Python virtual environment |
| `scripts/fpga-artifacts/` | Built artifacts (bitstream, firmware, test binaries, xtask) |
| `scripts/fpga-test-results/` | Test results (junit.xml) fetched from FPGA |

## Typical Workflow

```bash
cd scripts

# 1. Set up Python venv (one-time)
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# 2. Set up the FPGA board (after each board reboot)
python setup_fpga.py

# 3. Build and deploy test artifacts
./build_fpga_artifacts.sh --build-openssl --with-bitstream --deploy

# 4. SSH into the board and run tests
./run_fpga_tests.sh --bootstrap

# Or run a specific test
./run_fpga_tests.sh --filter "test_name"
```
