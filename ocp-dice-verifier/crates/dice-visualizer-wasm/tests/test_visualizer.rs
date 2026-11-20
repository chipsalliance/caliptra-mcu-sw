// Licensed under the Apache-2.0 license

use dice_visualizer_wasm::visualizer::parse_chain_to_view;

const CI_CERT_CHAIN: &[u8] = include_bytes!("../../../test-data/certificate_chain_slot_00.der");

#[test]
fn test_visualizer_on_ci_chain() {
    let output = parse_chain_to_view(CI_CERT_CHAIN);

    assert!(output.success, "Parsing failed: {:?}", output.error);
    assert_eq!(output.total_certs, 6);
    assert_eq!(output.certs.len(), 6);

    // Verify Tab Titles
    assert_eq!(output.certs[0].tab_title, "Root CA");
    assert_eq!(output.certs[1].tab_title, "IDevID");
    assert_eq!(output.certs[2].tab_title, "LDevID");
    assert_eq!(output.certs[3].tab_title, "FMC Alias");
    assert_eq!(output.certs[4].tab_title, "RT Alias");
    assert_eq!(output.certs[5].tab_title, "DPE Leaf");

    // Verify DICE extensions
    assert!(!output.certs[0].dice.has_dice); // Root has no DICE extensions
    assert!(!output.certs[1].dice.has_dice); // IDevID has no DICE extensions
    assert!(output.certs[2].dice.has_dice); // LDevID has UEID & EKU
    assert!(output.certs[2].dice.ueid_hex.is_some());

    assert!(output.certs[3].dice.has_dice); // FMC Alias has MultiTcbInfo
    assert_eq!(output.certs[3].dice.multi_tcb_info.len(), 3);
    // Raw wire DER value in Caliptra ROM/FMC static template (`(1 << 8) | svn` = 256)
    assert_eq!(output.certs[3].dice.multi_tcb_info[2].svn, Some(256));

    assert!(output.certs[4].dice.has_dice); // RT Alias has TcbInfo
    assert!(output.certs[4].dice.tcb_info.is_some());
    let rt_tcb = output.certs[4].dice.tcb_info.as_ref().unwrap();
    assert_eq!(rt_tcb.svn, Some(256));

    assert!(output.certs[5].dice.has_dice); // DPE Leaf has MultiTcbInfo
    assert!(!output.certs[5].dice.multi_tcb_info.is_empty());
    // DPE Leaf uses ML-DSA-87 signature and public key algorithms
    assert!(output.certs[5].sig_alg.contains("id-ml-dsa-87"));
    assert!(output.certs[5].sig_alg.contains("2.16.840.1.101.3.4.3.19"));
    assert!(output.certs[5]
        .public_key
        .algorithm
        .contains("id-ml-dsa-87"));

    // Verify Mermaid diagram contains nodes and click actions
    assert!(output.mermaid_diagram.contains("graph LR"));
    assert!(output.mermaid_diagram.contains("C0[\"<b>1. Root CA</b>"));
    assert!(output.mermaid_diagram.contains("C5[\"<b>6. DPE Leaf</b>"));
    assert!(output
        .mermaid_diagram
        .contains("click C0 call selectCertTab(0)"));
    assert!(output
        .mermaid_diagram
        .contains("click C5 call selectCertTab(5)"));

    // Verify JSON serialization
    let json = serde_json::to_string(&output).expect("Failed to serialize to JSON");
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("DPE Leaf"));
}
