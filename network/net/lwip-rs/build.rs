// Licensed under the Apache-2.0 license

//! Build script for lwip-rs
//! Compiles lwIP C sources and generates Rust bindings
//!
//! Supports two modes:
//! - Host (default): Uses Unix TAP port, links pthread/rt/util
//! - Bare-metal (feature "baremetal"): No OS, custom netif, cross-compiles for riscv32

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_default();
    let is_baremetal = env::var("CARGO_FEATURE_BAREMETAL").is_ok();
    let is_baremetal_ipv6 = env::var("CARGO_FEATURE_BAREMETAL_IPV6").is_ok();

    // Paths to lwIP
    let lwip_dir = manifest_dir.join("../lwip");
    let lwip_src = lwip_dir.join("src");
    let lwip_contrib = lwip_dir.join("contrib");
    let include_dir = manifest_dir.join("include");
    let baremetal_include_dir = include_dir.join("baremetal");

    // Build lwIP library
    let mut builder = cc::Build::new();
    builder.warnings(false);

    if is_baremetal {
        // Bare-metal build: use baremetal include dir (has arch/cc.h, lwipopts.h, etc.)
        // baremetal include dir must come first so its lwipopts.h and arch/ take precedence
        builder.include(&baremetal_include_dir);
        builder.include(lwip_src.join("include"));

        // Enable IPv6 for baremetal-ipv6 feature
        if is_baremetal_ipv6 {
            builder.define("LWIP_BAREMETAL_IPV6", "1");
        }

        // For riscv32 cross-compilation with riscv64-unknown-elf-gcc
        if target.contains("riscv32") {
            builder.compiler("riscv64-unknown-elf-gcc");
            builder.flag("-march=rv32imc");
            builder.flag("-mabi=ilp32");
            // Use picolibc for standard headers (string.h, etc.)
            builder.flag("--specs=picolibc.specs");
        }
    } else {
        // Host build: use standard include paths with Unix port
        builder.include(&include_dir);
        builder.include(lwip_src.join("include"));
        builder.include(lwip_contrib.join("ports/unix/port/include"));
    }

    // Core lwIP sources (same for both modes, minus TCP for baremetal)
    let core_sources_common = [
        "core/init.c",
        "core/def.c",
        "core/dns.c",
        "core/inet_chksum.c",
        "core/ip.c",
        "core/mem.c",
        "core/memp.c",
        "core/netif.c",
        "core/pbuf.c",
        "core/raw.c",
        "core/stats.c",
        "core/sys.c",
        "core/timeouts.c",
        "core/udp.c",
    ];
    for src in &core_sources_common {
        builder.file(lwip_src.join(src));
    }

    // TCP sources (host only - baremetal DHCP doesn't need TCP)
    if !is_baremetal {
        let tcp_sources = [
            "core/altcp.c",
            "core/altcp_alloc.c",
            "core/altcp_tcp.c",
            "core/tcp.c",
            "core/tcp_in.c",
            "core/tcp_out.c",
        ];
        for src in &tcp_sources {
            builder.file(lwip_src.join(src));
        }
    }

    // IPv4 sources
    let ipv4_sources = [
        "core/ipv4/autoip.c",
        "core/ipv4/dhcp.c",
        "core/ipv4/etharp.c",
        "core/ipv4/icmp.c",
        "core/ipv4/igmp.c",
        "core/ipv4/ip4.c",
        "core/ipv4/ip4_addr.c",
        "core/ipv4/ip4_frag.c",
        "core/ipv4/acd.c",
    ];
    for src in &ipv4_sources {
        builder.file(lwip_src.join(src));
    }

    // IPv6 sources (host or baremetal-ipv6)
    if !is_baremetal || is_baremetal_ipv6 {
        let ipv6_sources = [
            "core/ipv6/dhcp6.c",
            "core/ipv6/ethip6.c",
            "core/ipv6/icmp6.c",
            "core/ipv6/inet6.c",
            "core/ipv6/ip6.c",
            "core/ipv6/ip6_addr.c",
            "core/ipv6/ip6_frag.c",
            "core/ipv6/mld6.c",
            "core/ipv6/nd6.c",
        ];
        for src in &ipv6_sources {
            builder.file(lwip_src.join(src));
        }
    }

    // Netif sources
    if is_baremetal {
        // Only ethernet.c needed for bare-metal (plus ethip6 for IPv6)
        builder.file(lwip_src.join("netif/ethernet.c"));
    } else {
        let netif_sources = [
            "netif/ethernet.c",
            "netif/bridgeif.c",
            "netif/bridgeif_fdb.c",
        ];
        for src in &netif_sources {
            builder.file(lwip_src.join(src));
        }
    }

    // App sources (host only)
    if !is_baremetal {
        builder.file(lwip_src.join("apps/tftp/tftp.c"));
    }

    // Port sources
    if !is_baremetal {
        // Unix port sources
        let port_sources = [
            "ports/unix/port/sys_arch.c",
            "ports/unix/port/netif/tapif.c",
            "ports/unix/port/netif/sio.c",
            "ports/unix/port/netif/fifo.c",
        ];
        for src in &port_sources {
            builder.file(lwip_contrib.join(src));
        }
    }
    // For baremetal: sys_now, sys_arch_protect, and netif callbacks are provided by Rust code

    builder.compile("lwip");

    // Generate Rust bindings
    let mut bindgen_builder = bindgen::Builder::default();

    if is_baremetal {
        bindgen_builder = bindgen_builder
            .header(baremetal_include_dir.join("wrapper.h").to_string_lossy())
            .clang_arg(format!("-I{}", baremetal_include_dir.display()))
            .clang_arg(format!("-I{}", lwip_src.join("include").display()));

        // Tell clang to target riscv32 for correct struct layouts
        if target.contains("riscv32") {
            bindgen_builder = bindgen_builder
                .clang_arg("--target=riscv32")
                .clang_arg("-march=rv32imc")
                // Add GCC and picolibc include paths for clang to find stdint.h, string.h, etc.
                .clang_arg("-I/usr/lib/gcc/riscv64-unknown-elf/10.2.0/include")
                .clang_arg("-I/usr/lib/picolibc/riscv64-unknown-elf/include");
        }

        // Enable IPv6 defines for bindgen when baremetal-ipv6
        if is_baremetal_ipv6 {
            bindgen_builder = bindgen_builder
                .clang_arg("-DLWIP_BAREMETAL_IPV6=1");
        }
    } else {
        bindgen_builder = bindgen_builder
            .header(include_dir.join("wrapper.h").to_string_lossy())
            .clang_arg(format!("-I{}", include_dir.display()))
            .clang_arg(format!("-I{}", lwip_src.join("include").display()))
            .clang_arg(format!(
                "-I{}",
                lwip_contrib.join("ports/unix/port/include").display()
            ));
    }

    bindgen_builder = bindgen_builder
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("lwip_init")
        .allowlist_function("sys_check_timeouts")
        .allowlist_function("sys_timeouts_sleeptime")
        .allowlist_function("netif_add")
        .allowlist_function("netif_remove")
        .allowlist_function("netif_set_default")
        .allowlist_function("netif_set_up")
        .allowlist_function("netif_set_down")
        .allowlist_function("netif_set_link_up")
        .allowlist_function("netif_set_link_down")
        .allowlist_function("netif_set_status_callback")
        .allowlist_function("netif_set_link_callback")
        .allowlist_function("netif_input")
        .allowlist_function("ethernet_input")
        .allowlist_function("dhcp_start")
        .allowlist_function("dhcp_stop")
        .allowlist_function("dhcp_release")
        .allowlist_function("dhcp_set_struct")
        .allowlist_function("dhcp_supplied_address")
        .allowlist_function("ip4_addr_set_zero")
        .allowlist_function("ip4addr_ntoa.*")
        .allowlist_function("ip4addr_aton")
        .allowlist_function("pbuf_alloc")
        .allowlist_function("pbuf_free")
        .allowlist_function("pbuf_copy_partial")
        .allowlist_function("etharp_output")
        .allowlist_type("netif")
        .allowlist_type("dhcp")
        .allowlist_type("pbuf")
        .allowlist_type("pbuf_type")
        .allowlist_type("pbuf_layer")
        .allowlist_type("ip4_addr.*")
        .allowlist_type("ip_addr.*")
        .allowlist_type("err_t")
        .allowlist_type("err_enum_t")
        .allowlist_var("ERR_.*")
        .allowlist_var("NETIF_FLAG_.*")
        .allowlist_var("PBUF_.*")
        .derive_debug(true)
        .derive_default(true)
        .use_core();

    // Host-only bindings
    if !is_baremetal {
        bindgen_builder = bindgen_builder
            .allowlist_function("netif_create_ip6_linklocal_address")
            .allowlist_function("netif_ip6_addr_set_state")
            .allowlist_function("tftp_init_client")
            .allowlist_function("tftp_get")
            .allowlist_function("tftp_cleanup")
            .allowlist_function("tapif_init")
            .allowlist_function("tapif_poll")
            .allowlist_function("tapif_select")
            .allowlist_function("ip6addr_ntoa.*")
            .allowlist_function("ip6addr_aton")
            .allowlist_function("ethip6_output")
            .allowlist_type("ip6_addr.*")
            .allowlist_type("tftp_context")
            .allowlist_var("IP6_ADDR_.*")
            .allowlist_var("LWIP_IPV6_NUM_ADDRESSES");
    }

    // Baremetal IPv6 bindings
    if is_baremetal_ipv6 {
        bindgen_builder = bindgen_builder
            .allowlist_function("netif_create_ip6_linklocal_address")
            .allowlist_function("netif_ip6_addr_set_state")
            .allowlist_function("dhcp6_enable_stateless")
            .allowlist_function("dhcp6_disable")
            .allowlist_function("ip6addr_ntoa.*")
            .allowlist_function("ethip6_output")
            .allowlist_type("ip6_addr.*")
            .allowlist_var("IP6_ADDR_.*")
            .allowlist_var("LWIP_IPV6_NUM_ADDRESSES");
    }

    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Link libraries (host only)
    if !is_baremetal {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=util");
    }

    // Rerun if these change
    println!("cargo:rerun-if-changed=include/wrapper.h");
    println!("cargo:rerun-if-changed=include/lwipopts.h");
    println!("cargo:rerun-if-changed=include/baremetal/wrapper.h");
    println!("cargo:rerun-if-changed=include/baremetal/lwipopts.h");
    println!("cargo:rerun-if-changed=include/baremetal/arch/cc.h");
    println!("cargo:rerun-if-changed=include/baremetal/arch/sys_arch.h");
}
