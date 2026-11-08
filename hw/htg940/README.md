# HTG-940 FPGA bitstream (Caliptra 2.2 hardware)

This is an isolated HTG-940 / `xcvu13p-fhgb2104-3-e` build tree on
`main-2.1`. It does not change the VCK190 sources, the existing
`hw/caliptra-ss` submodule, or the 2.1 firmware. USB hardware support here is
specific to the imported 2.2 snapshot.

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
[submodule_pins.json](fpga/htg940/submodule_pins.json), including USB2
`87a1a3789604dd5a611693a6ba97fff871498593`, then verifies/applies the three
checksum-pinned RTL patches. The unused lwIP pin was omitted. Do not run
recursive submodule update on the prepared tree afterward: it would reset the
USB2 override. The helper refuses to replace an existing checkout.

## Manual CI

[bitstream-build-htg940.yml](../../.github/workflows/bitstream-build-htg940.yml)
uses the existing `bitstream-builder` runner label and
`/vck190-tools/Vivado/2024.2`. That runner must have UltraScale+ device
support and appropriate licensing for the XCVU13P. The upstream handoff used
a 128 GB memory allocation; resource availability still needs confirmation.
The workflow installs Python 3.12 for source preparation and ROM conversion;
the shared Vivado runner does not need a preinstalled Python interpreter.

The workflow is manual-only and also callable. Before the new workflow is
registered on the default branch, dispatch the existing FPGA workflow on the
HTG branch with `board=htg940`; its VCK190 job is skipped:

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

Other dispatches and pull requests retain the VCK190 build behavior.
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

CI uploads these outputs and the build logs, including reports on failure.
The upstream handoff did not close timing and did not qualify full USB
recovery. Bitstream generation is not timing or hardware qualification.

## Focused validation

```sh
python3 -m unittest discover -s hw/htg940/fpga/htg940_usb_min_ila -p 'test_*.py'
python3 -m unittest discover -s hw/htg940/tests -p 'test_*.py'
```
