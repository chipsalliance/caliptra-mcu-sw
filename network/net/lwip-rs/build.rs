// Licensed under the Apache-2.0 license

//! Build script for lwip-rs
//! Compiles lwIP C sources and generates Rust bindings

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Paths to lwIP
    let lwip_dir = manifest_dir.join("../lwip");
    let lwip_src = lwip_dir.join("src");
    let lwip_contrib = lwip_dir.join("contrib");
    let include_dir = manifest_dir.join("include");

    // Include paths
    let includes = [
        include_dir.clone(),
        lwip_src.join("include"),
        lwip_contrib.join("ports/unix/port/include"),
    ];

    // Core lwIP sources
    let core_sources = [
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
        "core/altcp.c",
        "core/altcp_alloc.c",
        "core/altcp_tcp.c",
        "core/tcp.c",
        "core/tcp_in.c",
        "core/tcp_out.c",
        "core/timeouts.c",
        "core/udp.c",
    ];

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

    // IPv6 sources
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

    // Netif sources
    let netif_sources = [
        "netif/ethernet.c",
        "netif/bridgeif.c",
        "netif/bridgeif_fdb.c",
    ];

    // App sources (TFTP)
    let app_sources = ["apps/tftp/tftp.c"];

    // Unix port sources
    let port_sources = [
        "ports/unix/port/sys_arch.c",
        "ports/unix/port/netif/tapif.c",
        "ports/unix/port/netif/sio.c",
        "ports/unix/port/netif/fifo.c",
    ];

    // Build lwIP library
    let mut builder = cc::Build::new();
    builder.warnings(false);

    // Add include paths
    for inc in &includes {
        builder.include(inc);
    }

    // Add core sources
    for src in &core_sources {
        builder.file(lwip_src.join(src));
    }

    // Add IPv4 sources
    for src in &ipv4_sources {
        builder.file(lwip_src.join(src));
    }

    // Add IPv6 sources
    for src in &ipv6_sources {
        builder.file(lwip_src.join(src));
    }

    // Add netif sources
    for src in &netif_sources {
        builder.file(lwip_src.join(src));
    }

    // Add app sources
    for src in &app_sources {
        builder.file(lwip_src.join(src));
    }

    // Add port sources
    for src in &port_sources {
        builder.file(lwip_contrib.join(src));
    }

    builder.compile("lwip");

    // Generate Rust bindings
    let bindgen_builder = bindgen::Builder::default()
        .header(include_dir.join("wrapper.h").to_string_lossy())
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg(format!("-I{}", lwip_src.join("include").display()))
        .clang_arg(format!(
            "-I{}",
            lwip_contrib.join("ports/unix/port/include").display()
        ))
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
        .allowlist_function("netif_create_ip6_linklocal_address")
        .allowlist_function("netif_ip6_addr_set_state")
        .allowlist_function("dhcp_start")
        .allowlist_function("dhcp_stop")
        .allowlist_function("dhcp_release")
        .allowlist_function("dhcp_set_struct")
        .allowlist_function("dhcp_supplied_address")
        .allowlist_function("dhcp6_enable_stateful")
        .allowlist_function("dhcp6_enable_stateless")
        .allowlist_function("dhcp6_disable")
        .allowlist_function("tftp_init_client")
        .allowlist_function("tftp_get")
        .allowlist_function("tftp_cleanup")
        .allowlist_function("tapif_init")
        .allowlist_function("tapif_poll")
        .allowlist_function("tapif_select")
        .allowlist_function("ip4_addr_set_zero")
        .allowlist_function("ip4addr_ntoa.*")
        .allowlist_function("ip4addr_aton")
        .allowlist_function("ip6addr_ntoa.*")
        .allowlist_function("ip6addr_aton")
        .allowlist_function("pbuf_alloc")
        .allowlist_function("pbuf_free")
        .allowlist_function("pbuf_copy_partial")
        .allowlist_function("etharp_output")
        .allowlist_function("ethip6_output")
        .allowlist_type("netif")
        .allowlist_type("dhcp")
        .allowlist_type("pbuf")
        .allowlist_type("pbuf_type")
        .allowlist_type("pbuf_layer")
        .allowlist_type("ip4_addr.*")
        .allowlist_type("ip6_addr.*")
        .allowlist_type("ip_addr.*")
        .allowlist_type("tftp_context")
        .allowlist_type("err_t")
        .allowlist_type("err_enum_t")
        .allowlist_var("ERR_.*")
        .allowlist_var("NETIF_FLAG_.*")
        .allowlist_var("PBUF_.*")
        .allowlist_var("IP6_ADDR_.*")
        .allowlist_var("LWIP_IPV6_NUM_ADDRESSES")
        .derive_debug(true)
        .derive_default(true)
        .use_core();

    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Link libraries
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=util");

    // Rerun if these change
    println!("cargo:rerun-if-changed=include/wrapper.h");
    println!("cargo:rerun-if-changed=include/lwipopts.h");
}
