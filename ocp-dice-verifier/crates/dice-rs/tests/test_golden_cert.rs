// Licensed under the Apache-2.0 license

use dice_rs::cert::DiceExtensions;

const GOLDEN_CERT_P384_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICSjCCAdCgAwIBAgIBADAKBggqhkjOPQQDAzATMREwDwYDVQQDDAhEUEUgTGVh
ZjAgFw0yMzAyMjcwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowEzERMA8GA1UEAwwI
RFBFIExlYWYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ4bnZ+pctxbJzWIP9zQhKc
iSpvzO/mEhQMgL/1npQ0aAGd2hblB5sMHZAB0jpiS23QiNDDgmOUGUeHQD6KfQfl
4i9+nAuOgPofr/XSi0u1l7Jn8LhwI8ph/IRUvd79Lg6jgfUwgfIwHwYDVR0jBBgw
FoAUugGgqszFrG+OSOiLIyZBOrh7nSUwHQYDVR0OBBYEFLoBoKrMxaxvjkjoiyMm
QTq4e50lMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMEEGBmeBBQUEBAEB
/wQ0MDIEMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAADBPBgZngQUFBAUERTBDMEGmPzA9BglghkgBZQMEAgIEMAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAKBggqhkjO
PQQDAwNoADBlAjEA7TV874v3QQ/r2ihVeqXwc0RwM2gOuPRnLh3sQahQwb1PssgV
+nI18TF5CceCGXPsAjAyhHRwJwvcmJ3HsTojIIz250JLK8cOIOWR25Z47NIbZhrG
9FSo46A1tOWvCZErEVY=
-----END CERTIFICATE-----
"#;

#[test]
fn test_parse_golden_dpe_cert() {
    let (_, pem) = x509_parser::pem::parse_x509_pem(GOLDEN_CERT_P384_PEM.as_bytes())
        .expect("Failed to parse PEM");

    let dice = DiceExtensions::from_der_cert(&pem.contents)
        .expect("Failed to parse DICE extensions from certificate");

    // Assert UEID extension is present
    let ueid = dice.ueid.expect("Expected UEID extension");
    assert_eq!(ueid.ueid.len(), 48); // 48 zero bytes in golden cert

    // Assert MultiTcbInfo extension is present
    let multi_tcb = dice
        .multi_tcb_info
        .expect("Expected MultiTcbInfo extension");
    let entries: Vec<_> = multi_tcb.iter().collect();
    assert_eq!(entries.len(), 1);

    // Verify first TcbInfo entry
    let tcb = &entries[0];
    let fwids: Vec<_> = tcb.fwids.clone().unwrap().collect();
    assert_eq!(fwids.len(), 1);

    // Hash algorithm is SHA-384: 2.16.840.1.101.3.4.2.2
    assert_eq!(
        fwids[0].hash_alg,
        asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2)
    );
    assert_eq!(fwids[0].digest.len(), 48);
}
