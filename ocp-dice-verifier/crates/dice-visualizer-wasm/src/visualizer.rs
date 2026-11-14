// Licensed under the Apache-2.0 license

use crate::model::*;
use dice_rs::cert::DiceExtensions;
use dice_rs::tcb_info::TcbInfo;
use spdm_cert_rs::{SpdmCertChain, SpdmExtensions};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Parses an SPDM certificate chain or concatenated DER blob into a VisualizerOutput model.
pub fn parse_chain_to_view(input: &[u8]) -> VisualizerOutput {
    let chain = match SpdmCertChain::parse(input) {
        Ok(c) => c,
        Err(e) => {
            return VisualizerOutput {
                success: false,
                total_certs: 0,
                has_spdm_header: false,
                root_hash_hex: None,
                certs: Vec::new(),
                mermaid_diagram: String::new(),
                error: Some(format!("Failed to parse certificate chain: {e}")),
            };
        }
    };

    let mut cert_views = Vec::new();

    for (idx, cert_der) in chain.certs.iter().enumerate() {
        match X509Certificate::from_der(cert_der) {
            Ok((_, cert)) => {
                let view = build_cert_view(idx, &cert, cert_der);
                cert_views.push(view);
            }
            Err(e) => {
                return VisualizerOutput {
                    success: false,
                    total_certs: chain.certs.len(),
                    has_spdm_header: chain.has_spdm_header,
                    root_hash_hex: chain.root_hash.as_ref().map(hex::encode),
                    certs: cert_views,
                    mermaid_diagram: String::new(),
                    error: Some(format!("Failed to parse certificate #{idx}: {e:?}")),
                };
            }
        }
    }

    let mermaid = build_mermaid_chain(&cert_views);

    VisualizerOutput {
        success: true,
        total_certs: cert_views.len(),
        has_spdm_header: chain.has_spdm_header,
        root_hash_hex: chain.root_hash.as_ref().map(hex::encode),
        certs: cert_views,
        mermaid_diagram: mermaid,
        error: None,
    }
}

fn build_cert_view(idx: usize, cert: &X509Certificate, der: &[u8]) -> ParsedCertificateView {
    let subject_str = cert.subject().to_string();
    let issuer_str = cert.issuer().to_string();
    let tab_title = determine_tab_title(idx, &subject_str);

    let serial_hex = format!("{:x}", cert.serial);
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let sig_alg = friendly_sig_alg_name(&cert.signature_algorithm.algorithm.to_id_string());

    let pub_key_raw = cert.public_key().algorithm.algorithm.to_id_string();
    let pub_key = PublicKeyInfoView {
        algorithm: friendly_pubkey_alg_name(&pub_key_raw),
        key_size_bits: Some(cert.public_key().raw.len() * 8),
    };

    // Extract DICE extensions
    let dice = match DiceExtensions::from_x509_cert(cert) {
        Ok(d) => convert_dice_view(&d),
        Err(_) => DiceView::default(),
    };

    // Extract SPDM extensions
    let spdm = match SpdmExtensions::from_x509(cert) {
        Ok(s) => SpdmView {
            has_hardware_identity: s.has_hardware_identity,
            hardware_identity_hex: s.hardware_identity.as_ref().map(hex::encode),
            is_mutable: s.is_mutable,
            has_device_info: s.has_device_info,
            device_info: s.device_info,
            eku_responder_auth: s.eku_responder_auth,
            eku_requester_auth: s.eku_requester_auth,
        },
        Err(_) => SpdmView::default(),
    };

    // Standard extensions (filter out specialized DICE and SPDM extensions)
    let mut standard_extensions = Vec::new();
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if oid.starts_with("2.23.133.") || oid.starts_with("1.3.6.1.4.1.412.274.") {
            continue;
        }
        let name = friendly_extension_name(&oid);
        standard_extensions.push(ExtensionView {
            oid,
            name,
            critical: ext.critical,
            value_summary: format!("{} bytes", ext.value.len()),
        });
    }

    let raw_pem = der_to_pem(der);

    ParsedCertificateView {
        index: idx,
        tab_title,
        subject: subject_str,
        issuer: issuer_str,
        serial_hex,
        not_before,
        not_after,
        sig_alg,
        public_key: pub_key,
        dice,
        spdm,
        standard_extensions,
        raw_pem,
        raw_hex_len: der.len(),
    }
}

fn determine_tab_title(idx: usize, subject: &str) -> String {
    let sub = subject.to_lowercase();
    if sub.contains("root") {
        "Root CA".to_string()
    } else if sub.contains("idevid") {
        "IDevID".to_string()
    } else if sub.contains("ldevid") {
        "LDevID".to_string()
    } else if sub.contains("fmc") {
        "FMC Alias".to_string()
    } else if sub.contains("rt alias") || sub.contains("runtime") {
        "RT Alias".to_string()
    } else if sub.contains("dpe") || sub.contains("leaf") {
        "DPE Leaf".to_string()
    } else {
        format!("Cert {}", idx + 1)
    }
}

fn convert_dice_view(d: &DiceExtensions) -> DiceView {
    let mut view = DiceView::default();
    let mut has_dice = false;

    if let Some(ref ueid) = d.ueid {
        view.ueid_hex = Some(hex::encode(ueid.ueid));
        has_dice = true;
    }

    if let Some(ref tcb) = d.tcb_info {
        view.tcb_info = Some(convert_tcb_info(tcb));
        has_dice = true;
    }

    if let Some(ref multi) = d.multi_tcb_info {
        for tcb in multi.iter() {
            view.multi_tcb_info.push(convert_tcb_info(&tcb));
            has_dice = true;
        }
    }

    for kp in &d.key_purposes {
        view.key_purposes.push(kp.to_string());
        has_dice = true;
    }

    view.has_dice = has_dice;
    view
}

fn parse_operational_flags(bs: &asn1::BitString) -> OperationalFlagsView {
    let bytes = bs.as_bytes();
    let raw_hex = hex::encode(bytes);
    let b0 = bytes.first().copied().unwrap_or(0);

    // In DER BIT STRING (X.690 Section 8.6.2), bit 0 is MSB (0x80), bit 1 is 0x40, etc.
    let not_configured = (b0 & 0x80) != 0;
    let not_secure = (b0 & 0x40) != 0;
    let recovery = (b0 & 0x20) != 0;
    let debug = (b0 & 0x10) != 0;

    let mut names = Vec::new();
    if not_configured {
        names.push("notConfigured");
    }
    if not_secure {
        names.push("notSecure");
    }
    if recovery {
        names.push("recovery");
    }
    if debug {
        names.push("debug");
    }

    let summary = if names.is_empty() {
        format!("None (0x{})", raw_hex)
    } else {
        format!("{} (0x{})", names.join(", "), raw_hex)
    };

    OperationalFlagsView {
        raw_hex,
        not_configured,
        not_secure,
        recovery,
        debug,
        summary,
    }
}

fn convert_tcb_info(tcb: &TcbInfo) -> TcbInfoView {
    let tcb_type = tcb.tci_type.map(|bytes| {
        if let Ok(s) = std::str::from_utf8(bytes) {
            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return s.to_string();
            }
        }
        format!("0x{}", hex::encode(bytes))
    });

    let flags = tcb.flags.as_ref().map(parse_operational_flags);
    let flags_mask_hex = tcb
        .operational_flags_mask
        .as_ref()
        .map(|bs| hex::encode(bs.as_bytes()));

    let mut view = TcbInfoView {
        vendor: tcb.vendor.as_ref().map(|s| s.as_str().to_string()),
        model: tcb.model.as_ref().map(|s| s.as_str().to_string()),
        version: tcb.version.as_ref().map(|s| s.as_str().to_string()),
        svn: tcb.svn,
        layer: tcb.layer,
        index: tcb.index,
        tcb_type,
        flags,
        flags_mask_hex,
        vendor_info_hex: tcb.vendor_info.map(hex::encode),
        fwids: Vec::new(),
        integrity_registers: Vec::new(),
    };

    if let Some(ref fwids) = tcb.fwids {
        for f in fwids.clone() {
            view.fwids.push(FwidView {
                hash_alg: friendly_hash_alg_name(&f.hash_alg.to_string()),
                digest_hex: hex::encode(f.digest),
            });
        }
    }

    if let Some(ref irs) = tcb.integrity_registers {
        for ir in irs.clone() {
            let mut digests = Vec::new();
            if let Some(ref d_seq) = ir.register_digests {
                for d in d_seq.clone() {
                    digests.push(FwidView {
                        hash_alg: friendly_hash_alg_name(&d.hash_alg.to_string()),
                        digest_hex: hex::encode(d.digest),
                    });
                }
            }
            view.integrity_registers.push(IntegrityRegisterView {
                name: ir.register_name.as_ref().map(|s| s.as_str().to_string()),
                num: ir.register_num,
                digests,
            });
        }
    }

    view
}

fn friendly_sig_alg_name(oid: &str) -> String {
    match oid {
        // NIST FIPS 204 / IETF RFC 9883 ML-DSA
        "2.16.840.1.101.3.4.3.19" => "id-ml-dsa-87 (2.16.840.1.101.3.4.3.19)".to_string(),
        "2.16.840.1.101.3.4.3.18" => "id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)".to_string(),
        "2.16.840.1.101.3.4.3.17" => "id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)".to_string(),

        // RFC 5758 / SECG ECDSA
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384 (1.2.840.10045.4.3.3)".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256 (1.2.840.10045.4.3.2)".to_string(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512 (1.2.840.10045.4.3.4)".to_string(),

        // RSA
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption (1.2.840.113549.1.1.11)".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption (1.2.840.113549.1.1.12)".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption (1.2.840.113549.1.1.13)".to_string(),

        // LMS / HSS
        "1.3.6.1.4.1.41112.1.5.4" => "id-alg-hss-lms-hashsig (1.3.6.1.4.1.41112.1.5.4)".to_string(),

        _ => oid.to_string(),
    }
}

fn friendly_pubkey_alg_name(oid: &str) -> String {
    match oid {
        // NIST FIPS 204 ML-DSA
        "2.16.840.1.101.3.4.3.19" => "id-ml-dsa-87 (2.16.840.1.101.3.4.3.19)".to_string(),
        "2.16.840.1.101.3.4.3.18" => "id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)".to_string(),
        "2.16.840.1.101.3.4.3.17" => "id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)".to_string(),

        // RFC 5480 Elliptic Curve
        "1.2.840.10045.2.1" => "id-ecPublicKey (1.2.840.10045.2.1)".to_string(),

        // RSA
        "1.2.840.113549.1.1.1" => "rsaEncryption (1.2.840.113549.1.1.1)".to_string(),

        _ => oid.to_string(),
    }
}

fn friendly_hash_alg_name(oid: &str) -> String {
    match oid {
        "2.16.840.1.101.3.4.2.2" => "SHA-384".to_string(),
        "2.16.840.1.101.3.4.2.1" => "SHA-256".to_string(),
        "2.16.840.1.101.3.4.2.3" => "SHA-512".to_string(),
        _ => oid.to_string(),
    }
}

fn friendly_extension_name(oid: &str) -> String {
    match oid {
        // RFC 5280 Section 4.2.1
        "2.5.29.14" => "id-ce-subjectKeyIdentifier".to_string(),
        "2.5.29.15" => "id-ce-keyUsage".to_string(),
        "2.5.29.17" => "id-ce-subjectAltName".to_string(),
        "2.5.29.18" => "id-ce-issuerAltName".to_string(),
        "2.5.29.19" => "id-ce-basicConstraints".to_string(),
        "2.5.29.30" => "id-ce-nameConstraints".to_string(),
        "2.5.29.31" => "id-ce-cRLDistributionPoints".to_string(),
        "2.5.29.32" => "id-ce-certificatePolicies".to_string(),
        "2.5.29.33" => "id-ce-policyMappings".to_string(),
        "2.5.29.35" => "id-ce-authorityKeyIdentifier".to_string(),
        "2.5.29.36" => "id-ce-policyConstraints".to_string(),
        "2.5.29.37" => "id-ce-extKeyUsage".to_string(),
        "2.5.29.54" => "id-ce-inhibitAnyPolicy".to_string(),

        // TCG DICE Attestation Architecture
        "2.23.133.5.4.1" => "tcg-dice-TcbInfo".to_string(),
        "2.23.133.5.4.4" => "tcg-dice-Ueid".to_string(),
        "2.23.133.5.4.5" => "tcg-dice-MultiTcbInfo".to_string(),

        // DMTF DSP0274 SPDM
        "1.3.6.1.4.1.412.274.1" => "id-DMTF-device-info".to_string(),
        "1.3.6.1.4.1.412.274.2" => "id-DMTF-hardware-identity".to_string(),
        "1.3.6.1.4.1.412.274.3" => "id-DMTF-eku-responder-auth".to_string(),
        "1.3.6.1.4.1.412.274.4" => "id-DMTF-eku-requester-auth".to_string(),
        "1.3.6.1.4.1.412.274.5" => "id-DMTF-mutable-certificate".to_string(),
        "1.3.6.1.4.1.412.274.6" => "id-DMTF-SPDM-extension".to_string(),
        _ => oid.to_string(),
    }
}

fn build_mermaid_chain(certs: &[ParsedCertificateView]) -> String {
    if certs.is_empty() {
        return "graph LR\n  Empty[No Certificates Found]".to_string();
    }

    let mut diagram = String::from("graph LR\n");

    // Add nodes
    for (i, c) in certs.iter().enumerate() {
        let title = format!("{}. {}", i + 1, c.tab_title);
        diagram.push_str(&format!(
            "  C{i}[\"<b>{title}</b><br/><small>{summary}</small>\"]\n",
            i = i,
            title = title,
            summary = escape_mermaid_text(&truncate_str(&c.subject, 30))
        ));
    }

    // Connect nodes in issuance chain
    for i in 0..certs.len().saturating_sub(1) {
        diagram.push_str(&format!("  C{} --> C{}\n", i, i + 1));
    }

    // Add interactive click callbacks for tab selection
    diagram.push('\n');
    for (i, c) in certs.iter().enumerate() {
        diagram.push_str(&format!(
            "  click C{i} call selectCertTab({i}) \"Switch to {title}\"\n",
            i = i,
            title = c.tab_title
        ));
    }

    // Styling
    diagram.push_str(
        "\n  classDef default fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;\n",
    );
    diagram.push_str(
        "  classDef active fill:#0284c7,stroke:#7dd3fc,stroke-width:3px,color:#ffffff;\n",
    );

    diagram
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn escape_mermaid_text(s: &str) -> String {
    s.replace('"', "'")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = encode_base64(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            pem.push_str(s);
            pem.push('\n');
        }
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut chunks = input.chunks_exact(3);

    for chunk in &mut chunks {
        let b = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(TABLE[((b >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((b >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((b >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(b & 0x3f) as usize] as char);
    }

    let rem = chunks.remainder();
    if rem.len() == 1 {
        let b = (rem[0] as u32) << 16;
        out.push(TABLE[((b >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((b >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let b = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(TABLE[((b >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((b >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((b >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }

    out
}
