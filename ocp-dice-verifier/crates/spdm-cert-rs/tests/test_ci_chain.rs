// Licensed under the Apache-2.0 license

use sha2::{Digest, Sha256, Sha384, Sha512};
use spdm_cert_rs::SpdmCertChain;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

const CI_CERT_CHAIN: &[u8] = include_bytes!("../../../test-data/certificate_chain_slot_00.der");

#[test]
fn test_parse_ci_concatenated_der_chain() {
    let chain = SpdmCertChain::parse(CI_CERT_CHAIN).expect("Failed to parse CI cert chain");

    assert_eq!(chain.len(), 6);
    assert!(!chain.has_spdm_header);
    assert!(chain.root_hash.is_none());

    // 0: Root CA
    let (_, cert0) = X509Certificate::from_der(&chain.certs[0]).unwrap();
    assert!(cert0.subject().to_string().contains("Test Root CA"));

    // 1: IDevID
    let (_, cert1) = X509Certificate::from_der(&chain.certs[1]).unwrap();
    assert!(cert1.subject().to_string().contains("IDevID"));

    // 2: LDevID
    let (_, cert2) = X509Certificate::from_der(&chain.certs[2]).unwrap();
    assert!(cert2.subject().to_string().contains("LDevID"));
    let dice2 = dice_rs::cert::DiceExtensions::from_x509_cert(&cert2).unwrap();
    assert!(dice2.ueid.is_some());

    // 3: FMC Alias
    let (_, cert3) = X509Certificate::from_der(&chain.certs[3]).unwrap();
    assert!(cert3.subject().to_string().contains("FMC Alias"));
    let dice3 = dice_rs::cert::DiceExtensions::from_x509_cert(&cert3).unwrap();
    assert!(dice3.ueid.is_some());
    assert!(dice3.multi_tcb_info.is_some());
    for (i, tcb) in dice3.multi_tcb_info.unwrap().iter().enumerate() {
        println!(
            ">>> FMC Alias Entry {}: svn={:?}, type={:?}",
            i,
            tcb.svn,
            tcb.tci_type.map(|b| String::from_utf8_lossy(b).to_string())
        );
    }

    // 4: RT Alias
    let (_, cert4) = X509Certificate::from_der(&chain.certs[4]).unwrap();
    assert!(cert4.subject().to_string().contains("Rt Alias"));
    let dice4 = dice_rs::cert::DiceExtensions::from_x509_cert(&cert4).unwrap();
    assert!(dice4.ueid.is_some());
    assert!(dice4.tcb_info.is_some());
    let tcb4 = dice4.tcb_info.unwrap();
    println!(
        ">>> RT Alias: svn={:?}, type={:?}",
        tcb4.svn,
        tcb4.tci_type
            .map(|b| String::from_utf8_lossy(b).to_string())
    );

    // 5: DPE Leaf
    let (_, cert5) = X509Certificate::from_der(&chain.certs[5]).unwrap();
    assert!(cert5.subject().to_string().contains("DPE Leaf"));
    let dice5 = dice_rs::cert::DiceExtensions::from_x509_cert(&cert5).unwrap();
    assert!(dice5.ueid.is_some());
    assert!(dice5.multi_tcb_info.is_some());
    let multi5 = dice5.multi_tcb_info.unwrap();
    for (i, tcb) in multi5.iter().enumerate() {
        let ir_info = if let Some(ref irs) = tcb.integrity_registers {
            let entries: Vec<_> = irs.clone().collect();
            format!(
                "{} entries: {:?}",
                entries.len(),
                entries
                    .iter()
                    .map(|ir| {
                        (
                            ir.register_name.as_ref().map(|s| s.as_str()),
                            ir.register_num,
                            ir.register_digests.as_ref().map(|d| d.clone().count()),
                        )
                    })
                    .collect::<Vec<_>>()
            )
        } else {
            "None".to_string()
        };

        println!(">>> DPE Leaf Entry {}: vendor={:?}, model={:?}, version={:?}, svn={:?}, type={:?}, integrity_registers={}",
            i,
            tcb.vendor.as_ref().map(|s| s.as_str()),
            tcb.model.as_ref().map(|s| s.as_str()),
            tcb.version.as_ref().map(|s| s.as_str()),
            tcb.svn,
            tcb.tci_type.map(|b| String::from_utf8_lossy(b).to_string()),
            ir_info
        );
    }
}

#[test]
fn test_parse_spdm_header_with_root_hash() {
    // Construct an SPDM GET_CERTIFICATE response buffer:
    // 2 bytes length + 2 bytes reserved + 48 bytes root hash + raw certs
    let root_hash = Sha384::digest(chain_root_cert());
    let mut spdm_payload = Vec::new();
    let total_len = (4 + 48 + CI_CERT_CHAIN.len()) as u16;

    spdm_payload.extend_from_slice(&total_len.to_le_bytes());
    spdm_payload.extend_from_slice(&[0u8, 0u8]); // Reserved
    spdm_payload.extend_from_slice(&root_hash);
    spdm_payload.extend_from_slice(CI_CERT_CHAIN);

    let chain =
        SpdmCertChain::parse(&spdm_payload).expect("Failed to parse SPDM chain with header");
    assert_eq!(chain.len(), 6);
    assert!(chain.has_spdm_header);
    assert_eq!(chain.root_hash.as_deref(), Some(root_hash.as_slice()));
}

#[test]
fn test_parse_spdm_header_sha256_and_sha512() {
    let root_cert = chain_root_cert();

    // SHA-256 (32-byte root hash)
    let root_hash_256 = Sha256::digest(&root_cert);
    let mut payload_256 = Vec::new();
    let total_len_256 = (4 + 32 + CI_CERT_CHAIN.len()) as u16;
    payload_256.extend_from_slice(&total_len_256.to_le_bytes());
    payload_256.extend_from_slice(&[0u8, 0u8]);
    payload_256.extend_from_slice(&root_hash_256);
    payload_256.extend_from_slice(CI_CERT_CHAIN);

    let chain_256 = SpdmCertChain::parse(&payload_256).expect("Failed to parse SHA-256 SPDM chain");
    assert_eq!(chain_256.len(), 6);
    assert!(chain_256.has_spdm_header);
    assert_eq!(
        chain_256.root_hash.as_deref(),
        Some(root_hash_256.as_slice())
    );

    // SHA-512 (64-byte root hash)
    let root_hash_512 = Sha512::digest(&root_cert);
    let mut payload_512 = Vec::new();
    let total_len_512 = (4 + 64 + CI_CERT_CHAIN.len()) as u16;
    payload_512.extend_from_slice(&total_len_512.to_le_bytes());
    payload_512.extend_from_slice(&[0u8, 0u8]);
    payload_512.extend_from_slice(&root_hash_512);
    payload_512.extend_from_slice(CI_CERT_CHAIN);

    let chain_512 = SpdmCertChain::parse(&payload_512).expect("Failed to parse SHA-512 SPDM chain");
    assert_eq!(chain_512.len(), 6);
    assert!(chain_512.has_spdm_header);
    assert_eq!(
        chain_512.root_hash.as_deref(),
        Some(root_hash_512.as_slice())
    );
}

#[test]
fn test_parse_spdm_subordinate_chain_with_external_root_hash() {
    // Per DSP0274 and libspdm (`libspdm_verify_certificate_chain_buffer`),
    // a chain on the wire may omit the self-signed Root CA and start with an
    // intermediate certificate (e.g. IDevID), while RootHash in the SPDM header
    // holds the hash of the external Root CA.
    let full = SpdmCertChain::parse(CI_CERT_CHAIN).unwrap();
    let root_hash = Sha384::digest(&full.certs[0]);
    let subordinate_der: Vec<u8> = full.certs[1..].concat();

    let mut spdm_payload = Vec::new();
    let total_len = (4 + 48 + subordinate_der.len()) as u16;
    spdm_payload.extend_from_slice(&total_len.to_le_bytes());
    spdm_payload.extend_from_slice(&[0u8, 0u8]);
    spdm_payload.extend_from_slice(&root_hash);
    spdm_payload.extend_from_slice(&subordinate_der);

    let parsed = SpdmCertChain::parse(&spdm_payload)
        .expect("Failed to parse subordinate SPDM chain with external root hash");
    assert_eq!(parsed.len(), 5);
    assert!(parsed.has_spdm_header);
    assert_eq!(parsed.root_hash.as_deref(), Some(root_hash.as_slice()));
}

fn chain_root_cert() -> Vec<u8> {
    let chain = SpdmCertChain::parse(CI_CERT_CHAIN).unwrap();
    chain.certs[0].clone()
}
