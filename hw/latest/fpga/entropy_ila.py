#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Materialize read-only, lab-only entropy probes without editing submodules.

Every probe is sampled once on the core clock, without a probe reset. No raw
entropy, generated words, keys, or unrestricted bus traffic is exported.
"""

import argparse
import hashlib
import json
from pathlib import Path


# Instrument only the RTL pinned by the PR2303 baseline. A new revision needs an
# explicit review of the signal names, widths, reset domains and disclosure.
RTL_REVISION = "a2192d99327a94ade30929315a94fe28bba598df"


def field(name, width, expression):
    return {"name": name, "width": width, "expression": expression}


# Fields are specified LSB first. Reserved high bits are zero. Keep each sampled
# vector intact, including constant bits, so the LTX and this layout agree.
PROBES = [
    {
        "name": "top",
        "source": "src/integration/rtl/caliptra_top.sv",
        "scope": "",
        "width": 32,
        "clock": "fpga_entropy_ila_sample_clk",
        # Do not fill the capture merely because a raw sample is marked valid.
        "event_mask": ((1 << 27) - 1) & ~(1 << 23),
        "fields": [
            field("powergood", 1, "cptra_pwrgood"),
            field("external_reset_n", 1, "cptra_rst_b"),
            field("noncore_reset_n", 1, "cptra_noncore_rst_b"),
            field("cpu_reset_n", 1, "cptra_uc_rst_b"),
            field("fatal_error", 1, "cptra_error_fatal"),
            field("security_zeroize", 1, "debug_lock_or_scan_mode_switch"),
            field("dual_enabled", 1, "dual_itrng_en_reg"),
            field("es1_enable_strap", 1, "itrng1_en"),
            field("fmc_phase_mubi", 4, "boot_flow_fmc"),
            field("runtime_phase_mubi", 4, "boot_flow_rt"),
            field("boot_error_mubi", 4, "boot_flow_error"),
            field("ready_for_fuses", 1, "ready_for_fuses"),
            field("ready_for_mailbox", 1, "ready_for_mb_processing"),
            field("ready_for_runtime", 1, "ready_for_runtime"),
            field("es0_sample_valid", 1, "entropy_src_rng_valid"),
            field("es0_rng_enable", 1, "entropy_src_rng_enable"),
            field("csrng_seed_request", 1, "csrng_hw_if_req.es_req"),
            field("csrng_seed_ack", 1, "csrng_hw_if_rsp.es_ack"),
        ],
    },
    {
        "name": "es_conf",
        "source": "src/entropy_src/rtl/entropy_src_core.sv",
        "scope": "entropy_src/u_entropy_src_core/",
        "width": 32,
        "clock": "clk_i",
        "fields": [
            field("fips_enable", 4, "reg2hw.conf.fips_enable.q"),
            field("fips_flag", 4, "reg2hw.conf.fips_flag.q"),
            field("rng_fips", 4, "reg2hw.conf.rng_fips.q"),
            field("rng_bit_enable", 4, "reg2hw.conf.rng_bit_enable.q"),
            field("threshold_scope", 4, "reg2hw.conf.threshold_scope.q"),
            field("entropy_data_reg_enable", 4, "reg2hw.conf.entropy_data_reg_enable.q"),
            field("rng_bit_sel", 8, "reg2hw.conf.rng_bit_sel.q"),
        ],
    },
    {
        "name": "es_windows",
        "source": "src/entropy_src/rtl/entropy_src_core.sv",
        "scope": "entropy_src/u_entropy_src_core/",
        "width": 32,
        "clock": "clk_i",
        "fields": [
            field("fips_window", 16, "health_test_fips_window"),
            field("bypass_window_bits", 16, "health_test_bypass_window"),
        ],
    },
    {
        "name": "es_thresholds",
        "source": "src/entropy_src/rtl/entropy_src_core.sv",
        "scope": "entropy_src/u_entropy_src_core/",
        "width": 112,
        "clock": "clk_i",
        "fields": [
            field("repcnt", 16, "repcnt_threshold_oneway"),
            field("repcnts", 16, "repcnts_threshold_oneway"),
            field("adaptp_hi", 16, "adaptp_hi_threshold_oneway"),
            field("adaptp_lo", 16, "adaptp_lo_threshold_oneway"),
            field("adaptps", 16, "adaptps_threshold_oneway"),
            field("alert_threshold", 16, "alert_threshold"),
            field("alert_threshold_inverse", 16, "alert_threshold_inv"),
        ],
    },
    {
        "name": "es_control",
        "source": "src/entropy_src/rtl/entropy_src_core.sv",
        "scope": "entropy_src/u_entropy_src_core/",
        "width": 32,
        "clock": "clk_i",
        "fields": [
            field("module_enable_mubi", 4, "reg2hw.module_enable.q"),
            field("sw_regupd", 1, "reg2hw.sw_regupd.q"),
            field("effective_regwen", 1, "es_hw_regwen"),
            field("threshold_oneway_mubi", 4, "reg2hw.threshold_oneway.q"),
            field("es_route_mubi", 4, "reg2hw.entropy_control.es_route.q"),
            field("es_type_mubi", 4, "reg2hw.entropy_control.es_type.q"),
        ],
    },
    {
        "name": "es_health",
        "source": "src/entropy_src/rtl/entropy_src_core.sv",
        "scope": "entropy_src/u_entropy_src_core/",
        "width": 32,
        "clock": "clk_i",
        "fields": [
            field("main_state", 9, "es_main_sm_state"),
            field("repcnt_fails", 4, "repcnt_fail_count"),
            field("repcnts_fails", 4, "repcnts_fail_count"),
            field("adaptp_hi_fails", 4, "adaptp_hi_fail_count"),
            field("adaptp_lo_fails", 4, "adaptp_lo_fail_count"),
            field("adaptps_fails", 4, "adaptps_fail_count"),
        ],
    },
    {
        "name": "es_locks",
        "source": "src/entropy_src/rtl/entropy_src_reg_top.sv",
        "scope": "entropy_src/u_entropy_src_reg_top/",
        "width": 8,
        "clock": "clk_i",
        "fields": [
            field("me_regwen", 1, "me_regwen_qs"),
            field("sw_regupd", 1, "sw_regupd_qs"),
            field("effective_regwen", 1, "regwen_qs"),
            field("alert_test_regwen", 1, "alert_test_regwen_qs"),
            field("module_enable_mubi", 4, "module_enable_qs"),
        ],
    },
    {
        "name": "combiner",
        "source": "src/entropy_combiner/rtl/entropy_combiner.sv",
        "scope": "entropy_combiner/",
        "width": 32,
        "clock": "clk",
        "fields": [
            field("state", 9, "state_q"),
            field("combine_enabled", 1, "combine_en_status"),
            field("effective_lock", 1, "ahb_locked"),
            field("ahb_lock_mubi", 4, "ahb_lock_mubi"),
            field("runtime_lock_backstop", 1, "rt_active_q"),
            field("zeroize", 1, "zeroize"),
            field("fips_policy", 2, "hwif_out.COMBINER_CTRL.es_fips_policy.value"),
            field("fips_cfg", 1, "hwif_out.COMBINER_CTRL.es_fips_cfg.value"),
            field("es0_valid", 1, "es0_valid_q"),
            field("es1_valid", 1, "es1_valid_q"),
            field("seed_request", 1, "csrng_hw_if_req_i.es_req"),
            field("seed_ack", 1, "csrng_hw_if_rsp_o.es_ack"),
            field("sha3_state_valid", 1, "sha3_state_valid"),
            field("sha3_error", 1, "sha3_error.valid"),
            field("fsm_error", 1, "combiner_fsm_error"),
            field("sha3_sparse_fsm_error", 1, "sha3_sparse_fsm_error"),
            field("sha3_counter_error", 1, "sha3_count_error"),
            field("sha3_storage_reset_error", 1, "sha3_storage_rst_error"),
            field("reset_n", 1, "reset_n"),
            field("powergood", 1, "cptra_pwrgood_i"),
        ],
    },
    {
        "name": "combiner_zero",
        "source": "src/entropy_combiner/rtl/entropy_combiner.sv",
        "scope": "entropy_combiner/",
        "width": 8,
        "clock": "clk",
        "fields": [
            field("es0_storage_zero", 1, "~(|es0_bits_q)"),
            field("es1_storage_zero", 1, "~(|es1_bits_q)"),
            field("digest_storage_zero", 1, "~(|digest_q)"),
            field("kat_message_zero", 1, "~(|kat_msg_q)"),
            field("kat_digest_zero", 1, "~(|kat_digest_q)"),
            field("kat_length_zero", 1, "~(|kat_msg_len_q)"),
            field("kat_digest_valid", 1, "kat_digest_valid_q"),
            field("kat_operation", 1, "op_is_kat_q"),
        ],
    },
]


PROBES.append(
    {
        "name": "cycles",
        "source": "src/integration/rtl/caliptra_top.sv",
        "scope": "",
        "width": 32,
        "clock": "fpga_entropy_ila_sample_clk",
        "events": False,
        "fields": [field("core_cycles_mod_2_32", 32, "fpga_entropy_ila_cycle_count")],
    }
)


def instrument(text, probes):
    if text.count("endmodule") != 1 or "fpga_entropy_ila_" in text:
        raise ValueError("expected one pristine RTL module")
    blocks = ["\n  // Lab-only observation flops. Never drive functional state.\n"]
    if any(p["name"] == "top" for p in probes):
        blocks.append(
            '  (* keep = "true" *) wire fpga_entropy_ila_sample_clk = clk;\n'
            "  logic [31:0] fpga_entropy_ila_cycle_count = '0;\n"
            "  always_ff @(posedge fpga_entropy_ila_sample_clk)\n"
            "    fpga_entropy_ila_cycle_count <= fpga_entropy_ila_cycle_count + 32'd1;\n"
        )
    for probe in probes:
        fields = probe["fields"]
        used = sum(f["width"] for f in fields)
        if used > probe["width"]:
            raise ValueError(f"probe {probe['name']} overflows")
        expressions = [f["expression"] for f in reversed(fields)]
        if used < probe["width"]:
            expressions.insert(0, f"{probe['width'] - used}'b0")
        signal = "fpga_entropy_ila_" + probe["name"]
        value = "{" + ", ".join(expressions) + "}"
        blocks.append(
            f'  (* mark_debug = "true", dont_touch = "true" *) '
            f"logic [{probe['width'] - 1}:0] {signal};\n"
            f"  always_ff @(posedge {probe['clock']})\n"
            f"    {signal} <= {value};\n"
        )
        if probe.get("events", True):
            mask = probe.get("event_mask", (1 << probe["width"]) - 1)
            blocks.append(
                f'  (* mark_debug = "true", dont_touch = "true" *) logic {signal}_changed;\n'
                f"  always_ff @(posedge {probe['clock']})\n"
                f"    {signal}_changed <= |(({signal} ^ {value}) & {probe['width']}'h{mask:x});\n"
            )
    return text.replace("endmodule", "".join(blocks) + "\nendmodule")


def generate(rtl_root, output_dir):
    # No source updates, git mutations, or relaxation of the dependency pin.
    import subprocess

    revision = subprocess.check_output(
        ["git", "-C", str(rtl_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != RTL_REVISION:
        raise ValueError(f"unsupported entropy ILA RTL revision: {revision}")
    grouped = {}
    for probe in PROBES:
        grouped.setdefault(probe["source"], []).append(probe)
    clean = subprocess.run(
        ["git", "-C", str(rtl_root), "diff", "--quiet", "HEAD", "--", *grouped],
        check=False,
    )
    if clean.returncode != 0:
        raise ValueError("reviewed entropy ILA source files must match the pinned commit")
    sources = []
    rendered = {}
    for relative, probes in grouped.items():
        source = rtl_root / relative
        # Read bytes for provenance; normalize line endings only in generated copies.
        raw = source.read_bytes()
        rendered[source.name] = instrument(raw.decode().replace("\r\n", "\n"), probes)
        sources.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (output_dir / name).write_text(text)
    layout = {
        "schema_version": 1,
        "rtl_revision": revision,
        "lab_only": True,
        "topology": "ES0 only; ES1 enable remains tied low",
        "sample_latency_cycles": 1,
        "sample_clock": "ungated core clock (CG_EN=FALSE)",
        "zeroization_scope": "combiner storage only, not whole SHA3/CSRNG state",
        "sources": sources,
        "probes": [],
    }
    tcl_probes = []
    for index, probe in enumerate(PROBES):
        item = {k: v for k, v in probe.items() if k not in ("clock", "fields")}
        item["port"] = f"probe{index}"
        item["signal"] = "fpga_entropy_ila_" + probe["name"]
        item["fields"] = []
        offset = 0
        for entry in probe["fields"]:
            item["fields"].append({**entry, "lsb": offset})
            offset += entry["width"]
        layout["probes"].append(item)
        # Only controlled identifiers/paths appear here, never arbitrary user Tcl.
        tcl_probes.append(f"    {{{item['signal']} {probe['width']} {{{probe['scope']}}}}}")
    events = [p for p in PROBES if p.get("events", True)]
    layout["event_port"] = f"probe{len(PROBES)}"
    layout["event_bits"] = [p["name"] for p in events]
    layout["event_latency_cycles"] = 1
    (output_dir / "entropy_ila_layout.json").write_text(json.dumps(layout, indent=2) + "\n")
    (output_dir / "entropy_ila_probes.tcl").write_text(
        "# Licensed under the Apache-2.0 license\n"
        "# Generated by entropy_ila.py; probe order matches entropy_ila_layout.json.\n"
        "set entropy_ila_probes {\n" + "\n".join(tcl_probes) + "\n}\n"
        "set entropy_ila_events {\n"
        + "\n".join(f"    {{fpga_entropy_ila_{p['name']}_changed {{{p['scope']}}}}}" for p in events)
        + "\n}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    generate(args.rtl_root, args.output_dir)


if __name__ == "__main__":
    main()
