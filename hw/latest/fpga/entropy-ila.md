# Lab-only entropy reset capture

This draft layers ES0-focused observation on PR #2303's tested FPGA integration.
It does not change submodule pins, entropy policy, security checks, the host-fed
noise FIFO or the constant-low ES1 enable. It is **not a production image**.

## Build and artifacts

The 2.2 workflow requests `entropy-ila: true`. The reusable workflow builds only
its full/nonsegmented variant. Other callers retain the original defaults.
Equivalent Vivado 2024.2 invocation, after initializing the pinned submodules:

```sh
cd hw/latest/fpga
vivado -mode batch -source fpga_configuration.tcl \
  -tclargs BUILD=TRUE SEGMENTED=FALSE ENTROPY_ILA=TRUE
```

`ITRNG=TRUE`, `CG_EN=FALSE` and `DEBUG=FALSE` are required. The broad `DEBUG` path
is deliberately not enabled: general AXI probes can capture sensitive traffic.
`entropy_ila.py` accepts only the reviewed RTL revision, generates observation
copies under `caliptra_build/entropy_ila/`, and leaves submodules untouched.
The implementation pre-hook refuses missing, duplicate or ambiguous probe bits.

Download **both artifacts from the same successful standard job**:

- `caliptra-bitstream-2.2-false`: XSA/PDI, `entropy_ila.ltx`,
  `entropy_ila_layout.json`, `entropy_ila_connected.txt` and timing summary.
- `caliptra-bitstream-bundle-2.2-standard`: original provenance bundle/manifest.

Keep those files together with their checksums and the CI commit/run identifiers.
The LTX is specific to the implemented image, not a reusable generic probe map.
Check timing and the connected-net report before interpreting captures. A green
build does not establish timing signoff or hardware correctness.

Use the previously validated full-PDI Bootgen packaging route for this VCK190.
Reusing reference ARM payloads/DTB requires checking compatibility. Do not use a
segmented PDI with that packager, change source pins to hide a mismatch, or
replace boot components blindly. Reserve the shared board across loading,
testing and verified stock restoration. Use host-driven testing after Linux/SSH
is available, not the previously problematic boot-time test/restore services.

## What is captured

The machine-readable layout is authoritative: each field gives its port, width,
LSB and RTL expression. All observation flops sample the same ungated core clock,
add **one observation cycle**, and have no Caliptra reset of their own. Constant
bits are deliberately retained to keep the layout stable.

| Port | Contents |
| --- | --- |
| 0 | Power/reset domains, boot phases, fatal/zeroize indication, topology and entropy handshake/valid flags |
| 1 | ES0 `CONF` in ABI-4 bit order |
| 2 | ES0 FIPS/bypass windows |
| 3 | Effective REPCNT, REPCNTS, ADAPTP high/low, ADAPTPS and alert threshold/inverse |
| 4 | Module enable, source routing/type, one-way policy and effective write gating |
| 5 | ES0 main state and per-test alert fail counts |
| 6 | Actual register-block ME_REGWEN, SW_REGUPD, REGWEN, alert-test lock and module enable |
| 7 | Combiner FSM, programmed/effective lock, runtime backstop, policy, zeroize and handshake/error flags |
| 8 | Boolean zero predicates for combiner seed/digest/KAT storage and KAT-valid/operation flags |
| 9 | Free-running core-cycle timestamp modulo 2^32, not reset by Caliptra warm reset |
| 10 | Change flags for ports 0 through 8, in that order |

No raw samples, seed values, generated words, DRBG keys or unrestricted buses are
exported. This is still privileged lab instrumentation: do not use production
secrets. The predicates on port 8 cover the combiner's explicitly listed storage,
**not the complete SHA3 engine or CSRNG state**. A zero predicate remaining true
through a test does not establish that nonzero state was exercised first.

## Capturing in Hardware Manager

ILA capture needs a supported JTAG cable/server connection and Vivado Hardware
Manager (or the appropriate Lab tooling). The ARM64 recovery host currently has
no installed `hw_server`; a working JTAG transport must be established before
claiming ILA capture. Linux register-readback tests do not require that tooling.

1. Load the packaged image using the established board procedure. Attach the
   matching `entropy_ila.ltx`; do not program the FPGA a second time through
   Hardware Manager while the host test is running.
2. Select the single `entropy_ila` core. Configure the storage qualifier to
   capture when the **whole port-10 change vector is nonzero**. The cycle counter
   is excluded from that qualifier. Port 0's raw sample-valid transitions are
   also excluded to avoid filling the buffer with routine sample traffic.
3. Arm before the host requests reset. Trigger on the sampled noncore-reset
   assertion (port 0 bit 2 goes low), with pre-trigger history. Configure trigger
   and capture comparators consistently; confirm that the change-qualified mode
   really is active, rather than assuming an 8192-sample continuous trace spans
   the boot.
4. Run the acknowledged MCU-quiescence/subsystem-reset protocol. Preserve the
   minimum reset pulse; the old 1 microsecond helper was below the pinned reset
   contract. The validated lab helper uses readback and a 10 microsecond hold.
5. Stop/upload an incomplete capture explicitly after the test if the sparse
   event stream has not filled the buffer. Do not wait indefinitely for 8192
   changes. Export CSV/WDB and correlate timestamps with firmware milestones.

A change event and its sampled payload have the same observation latency. The
cycle timestamp lets a sparse capture distinguish a one-cycle zeroization delay
from a long interval with no stored samples; ordinary sample indices cannot.
JTAG transport, exact Hardware Manager setup and actual FPGA observations remain
hardware-validation tasks, not properties established by this build.

## Initial hardware checks

- Read non-default, source-appropriate ES0 configuration and locks before ROM
  handoff and at runtime, then compare again after acknowledged warm reset.
- Confirm rejected configuration writes with effective readback, not just an
  unsuccessful boot. Turning MODULE_ENABLE off must not unlock SW_REGUPD.
- A full warm reset may reset source registers/locks; verify trusted restoration
  before use. A firmware-update reset has a different reset-domain contract.
- Use the existing host-fed ES0 FIFO for controlled good/stuck/biased and
  missing-sample inputs. Distinguish health rejection from a progress timeout;
  never weaken thresholds or bypass authentication/KAT/CFI to obtain a pass.
- Observe the combiner KAT/lock lifecycle in bypass topology. ES1 remains off;
  this image cannot validate dual-source operational combining. Additional
  internal SHA3/CSRNG zeroization assertions need separately reviewed probes.

## Delivery scope

This draft is only for obtaining the bitstream and matching probe artifacts.
It does not run precheckin, firmware suites, FPGA tests or board programming.
