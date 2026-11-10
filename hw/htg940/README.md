# HTG-940 FPGA bitstream (Caliptra 2.2 hardware)

This is an isolated HTG-940 / `xcvu13p-fhgb2104-3-e` build tree on
`main-2.1`. It does not change the VCK190 sources, the existing
`hw/caliptra-ss` submodule, or the 2.1 firmware. USB hardware support here is
specific to the selected 2.2 hardware snapshot.

## Source provenance

The required FPGA sources were imported from
[faydn23/caliptra-mcu-sw@1d79b4a](https://github.com/faydn23/caliptra-mcu-sw/tree/1d79b4a636438d3bdfcf7b273e81ea4a93ae739a/hw/fpga).
That snapshot contains these four integration commits, oldest first:

- `0a58db642505737b3a339a2c0d1f35029507065a`
- `e17f48fa0923f3f5f8bd856df27e4615976d57e6`
- `52a124ef8b37264db73fa0d4e7528e2eb45567af`
- `1d79b4a636438d3bdfcf7b273e81ea4a93ae739a`

Only the full-system HTG build dependencies are imported. Historical build
scripts, VCK190 changes, BRAM flash-driver replacements, ROM bring-up changes,
and fixed-key development provisioning are deliberately not applied to the
2.1 software. The full profile enables Caliptra core/crypto, MCU, USB2, a
40 MHz core clock, explicit ULPI IOBUFs, and two ILAs.

[prepare_sources.sh](prepare_sources.sh) creates an independent, ignored
`caliptra-ss` checkout beside `fpga`. It fetches the exact commits in
[submodule_pins.json](fpga/htg940/submodule_pins.json):

- upstream `chipsalliance/caliptra-ss/main` at
  `b9909edc83eefbbbd01d1616720dd2500a807eac`;
- its Caliptra RTL `f9bc5ab97b885b5e31ccb062eca16634a8e61b5a`
  and matching Adams Bridge;
- its USB2 Hub 2.6 `97aa9616f50d6adfb17e45053d1f16feb44792d7`,
  I3C, and remaining recursive dependencies.

The helper verifies/applies two checksum-pinned synthesis patches: explicit
AES array slices for Vivado and ULPI-only USB configuration. The former
subsystem AXI-filter compatibility patch is obsolete; native upstream fuse
and USB access policies are retained. The SHA accelerator lock fix is
already upstream. The build-local subsystem-top patch retains the FPGA I3C
clock/reset adaptation without reverting upstream interface/policy changes.
The helper refuses to replace an existing checkout. Prepare a fresh tree
when changing snapshots; do not reuse an older patched checkout.

## Manual CI

[bitstream-build-htg940.yml](../../.github/workflows/bitstream-build-htg940.yml)
uses the existing `bitstream-builder` runner label and
`/vck190-tools/Vivado/2024.2`. That runner must have UltraScale+ device
support and appropriate licensing for the XCVU13P. The upstream handoff used
a 128 GB memory allocation; resource availability still needs confirmation.
The workflow installs Python 3.12 for source preparation and ROM conversion;
the shared Vivado runner does not need a preinstalled Python interpreter.
All Tcl subprocesses use the explicit `HTG_PYTHON` executable, not Vivado's
older bundled Python. The shared command prefix includes Python's `-E` flag
to ignore Vivado's `PYTHONHOME`/`PYTHONPATH` overrides without changing
Vivado's own environment. Local builds require Python 3.9 or newer.

The workflow is manual-only and also callable. Before the new workflow is
registered on the default branch, dispatch the existing FPGA workflow on the
HTG branch with `board=htg940`:

```sh
gh workflow run bitstream-build.yml \
  --repo chipsalliance/caliptra-mcu-sw \
  --ref htg940-bitstream-main-2.1 -f board=htg940
```

Once the standalone workflow is registered, it can be dispatched directly:

```sh
gh workflow run bitstream-build-htg940.yml \
  --repo chipsalliance/caliptra-mcu-sw --ref <branch>
```

This debug-only branch disables unrelated workflows by renaming them to
`*.yml.disabled`. Its dispatch entry point is manual-only and invokes only
the HTG-940 build; there is no VCK190 job or pull-request trigger. Restore
the unrelated workflows and normal dispatch behavior before merging this
branch into a shared development branch.
HTG builds are serialized per branch and never cancel an in-progress build.
HTG artifacts are not sent through the VCK190 manifest/GCS publishing path.

**CI currently uses explicitly requested all-zero placeholders:**

- `caliptra_rom.bin`: 98,304 bytes
- `mcu_rom.bin`: 131,072 bytes
- `flash_image.bin`: 2,097,152 bytes, filling the entire firmware BRAM

**The resulting bitstream is not bootable and does not validate USB recovery.**
Inputs are clearly identified in the workflow warning, summary, artifact name,
and build metadata, with their SHA-256 hashes. No firmware is committed.

## Local build with supplied firmware

```sh
bash hw/htg940/prepare_sources.sh
python3 hw/htg940/fpga/htg940/prepare_sources.py --check
export HTG_PYTHON="$(command -v python3)"
source /vck190-tools/Vivado/2024.2/settings64.sh
cd hw/htg940/fpga
vivado -mode batch -source htg940/run_full.tcl \
  -tclargs BUILD_NAME=build_full_local FW_IMAGE_DIR=/absolute/writable/firmware IMPLEMENT
```

Supply exact-size Caliptra and MCU ROM binaries plus a compatible
`flash_image.bin` of at most 2 MiB. Real firmware needs to match the 2.2 RTL
and HTG BRAM memory map; stock VCK190/2.1 firmware is not qualified for this
board. Converters regenerate ROM MEM and flash COE files in that directory.
Use a new `build_full_<suffix>` name for each build; existing outputs are
preserved rather than overwritten.

Outputs under `fpga/htg940_usb_min_ila/build_full_<suffix>/caliptra_htg940_project.runs/impl_1`:

- `htg940_board_top.bit`
- `htg940_usb_dual_ila.ltx`
- `htg940_board_top.mmi`
- `htg940_timing_summary.rpt` and `htg940_drc.rpt`

CI uploads bitstream/debug artifacts only after all three nonempty outputs
are validated. Build logs and reports are uploaded even on failure.
The upstream handoff did not close timing and did not qualify full USB
recovery. Bitstream generation is not timing or hardware qualification.

## ULPI startup debug

Use the BIT, LTX, and MMI from the **same build**, and insert compatible real
firmware before testing. The artifact includes the revision manifest and
[probe_schema.tcl](fpga/htg940_usb_min_ila/probe_schema.tcl); the Vivado log
prints every resolved probe name and index (`HTG_ILA`).

- `ulpi_min_ila` uses the selected PHY `pie_clk`. It captures actual pad
  DATA/DIR/NXT/STP, drive enable, the request synchronizer stages, current
  and next startup state, registered DIR/NXT/RXDATA, power/reset detection,
  and both extended-register write/read pending bits.
- `usb_core_ila` and the debug hub use the free-running 40 MHz core clock.
  The source request is now the **hub** gateway (`usbreg_phy_*`), not the
  disconnected Device 0 gateway. Hub bus-write address/data, PLL/hub control,
  return handshake, divided ULPI-clock activity, external PHY reset
  input/output, and synchronized DIR/NXT/STP remain observable even if the
  PHY clock stops. The pin snapshot is `{DIR, NXT, STP}` (bits 2, 1, 0);
  it is delayed and can miss short transitions, not a replacement for the
  PHY-clock waveform. The external reset input is sampled asynchronously.

The named state monitors encode the RTL enum ordinal directly, independent
of Vivado's FSM encoding or optional vendor debug ports:

| Hex | `htg_ulpi_state` / `htg_ulpi_state_next` |
|---|---|
| 00 | `ULPI_OPER_RESET_PWR_INIT` |
| 01 | `ULPI_OPER_RESET_IREG_WR_TX_CMD` |
| 02 | `ULPI_OPER_RESET_REG_WR_TX_DATA` |
| 03 | `ULPI_OPER_RESET_WF_START_RESET_PHY` |
| 04 | `ULPI_OPER_RESET_WF_END_RESET_PHY` |
| 05 | `ULPI_OPER_RESET_WF_RXCMD_UPDATE` |
| 06 | `ULPI_OPER_RESET_CMD_RCV` |
| 07 | `ULPI_OPER_IDLE` |
| 09 / 0A / 0B | Extended write command / address / data |
| 0D / 0E / 0F | Extended read command / address / data |

For scratch-write capture, arm both ILAs **before** releasing the subsystem
from reset. Use capture mode ALWAYS and trigger `usbreg_phy_start == 1`
(core ILA) and `phy_start == 1` (ULPI ILA), optionally qualified by address
`0x16` and write `1`. The expected source data is `0xA5`; the hub register
write uses word address `0x0F` (byte offset `0x103C`), with prepare/start
values `0x8100A516` / `0x8300A516`.

For the state-05 startup hang, hold the subsystem in reset, arm the core ILA
on the rising edge of `PHY_RESET_N_OUTPUT`, then release reset. Separately
capture the ULPI ILA on entry to state 05, with pre-trigger samples, to see
the preceding reset/RXCMD sequence. State 05 advances to 06 when registered
DIR is 1 and NXT is 0, then to idle when DIR is 0. If the ULPI ILA reports a
stopped clock, use the core ILA's clock-activity and reset traces first;
removing a trigger cannot make a stopped sampling clock run.

## Focused validation

These tests require Python 3.9 or newer, Git, `patch`, and `tclsh` (the `tcl`
package on Debian/Ubuntu). CI installs Tcl when it is absent from the runner,
using root directly or non-interactive sudo for an unprivileged runner.
Prepare the isolated RTL first to include the real-source debug-generation
and FPGA-top patch tests.

```sh
python3 -m unittest discover -s hw/htg940/fpga/htg940_usb_min_ila -p 'test_*.py'
python3 -m unittest discover -s hw/htg940/tests -p 'test_*.py'
```
