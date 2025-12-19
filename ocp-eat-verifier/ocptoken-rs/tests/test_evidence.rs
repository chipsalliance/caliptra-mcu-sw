// Licensed under the Apache-2.0 license

use coset::{iana::Algorithm, CborSerializable, CoseSign1Builder, HeaderBuilder};

use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
    x509::{X509NameBuilder, X509},
};

use ocptoken::token::evidence::Evidence;

use coset::cbor::value::Value;

use openssl::ecdsa::EcdsaSig;

#[test]
fn decode_and_verify_cose_sign1() {
    // 1️ Generate ECC P-384 key pair
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    // 2️ Create X.509 certificate from public key
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "test-cert").unwrap();
    let name = name.build();

    let mut cert_builder = X509::builder().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder.set_issuer_name(&name).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();
    cert_builder.sign(&pkey, MessageDigest::sha384()).unwrap();

    let cert = cert_builder.build();
    let cert_der = cert.to_der().unwrap();

    // 3️ Dummy payload
    let payload = b"dummy payload for COSE signature";

    // 4️ Create COSE_Sign1 structure
    let cose = CoseSign1Builder::new()
        .payload(payload.to_vec())
        .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
        .unprotected(
            HeaderBuilder::new()
                // x5chain = label 33
                .value(33, Value::Array(vec![Value::Bytes(cert_der.clone())]))
                .build(),
        )
        .create_signature(&[], |msg| {
            let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
            signer.update(msg).unwrap();

            let der_sig = signer.sign_to_vec().unwrap();

            // DER → raw r||s (COSE format)
            let sig = EcdsaSig::from_der(&der_sig).unwrap();
            let r = sig.r().to_vec_padded(48).unwrap();
            let s = sig.s().to_vec_padded(48).unwrap();
            [r, s].concat()
        })
        .build();

    // 5️ Encode to CBOR
    let encoded = cose.to_vec().unwrap();

    // 6️ Decode + verify
    let evidence = Evidence::decode(&encoded);

    assert!(
        evidence.is_ok(),
        "COSE_Sign1 signature verification should succeed"
    );
}
