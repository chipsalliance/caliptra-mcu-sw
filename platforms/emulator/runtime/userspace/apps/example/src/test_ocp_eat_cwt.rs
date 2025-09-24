// Licensed under the Apache-2.0 license

extern crate alloc;

use core::fmt::Write;
use libapi_caliptra::certificate::{CertContext, KEY_LABEL_SIZE};
use libapi_caliptra::crypto::asym::{ecdsa::Ecdsa, AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use libapi_caliptra::error::CaliptraApiResult;
use libapi_caliptra::evidence::ocp_eat_claims::{OcpEatCwt, OcpEatType};
use romtime::{println, test_exit};

const TEST_DPE_CERT_LABEL: [u8; KEY_LABEL_SIZE] = [0x44; KEY_LABEL_SIZE];

pub async fn test_ocp_eat_cwt() {
    let nonce: [u8; 32] = [0xAB; 32];
    let ocp_cwt = match OcpEatCwt::new(
        OcpEatType::EatClaims,
        AsymAlgo::EccP384,
        &nonce,
        &TEST_DPE_CERT_LABEL,
        "CN=Test DPE Attestation Key",
    ) {
        Ok(cwt) => cwt,
        Err(err) => {
            println!("Failed to create OCP EAT CWT: {:?}", err);
            test_exit(1);
        }
    };

    let mut ocp_cwt_slice = [0u8; 4096];

    let ocp_cwt_size = match ocp_cwt.generate(&mut ocp_cwt_slice).await {
        Ok(size) => size,
        Err(err) => {
            println!("Failed to generate OCP EAT CWT: {:?}", err);
            test_exit(1);
        }
    };

    // let recovered_ocp_cwt = match CoseSign1::from_slice(&ocp_cwt_slice[..ocp_cwt_size]) {
    //     Ok(cose) => cose,
    //     Err(err) => {
    //         println!("Failed to parse generated CWT: {:?}", err);
    //         test_exit(1);
    //     }
    // };
    // let mut cert_ctx = CertContext::new();
    // let mut pubkey_x = [0u8; 48];
    // let mut pubkey_y = [0u8; 48];
    // let mut cert_buf = [0u8; 1024];

    // let size = cert_ctx
    //     .certify_key(
    //         &mut cert_buf,
    //         Some(&TEST_DPE_CERT_LABEL),
    //         Some(&mut pubkey_x),
    //         Some(&mut pubkey_y),
    //     )
    //     .await
    //     .map_err(|e| {
    //         println!("Failed to get DPE leaf cert: {:?}", e);
    //         test_exit(1);
    //     })
    //     .unwrap();

    // if !verify_protected_header(&recovered_ocp_cwt.protected.header) {
    //     println!("Protected header verification failed");
    //     test_exit(1);
    // }

    // if !verify_unprotected_header(&recovered_ocp_cwt.unprotected, &cert_buf[..size]).await {
    //     println!("Unprotected header verification failed");
    //     test_exit(1);
    // }

    // let payload = match recovered_ocp_cwt.payload {
    //     Some(claims) => claims,
    //     None => {
    //         println!("Missing payload in CWT");
    //         test_exit(1);
    //     }
    // };

    // let message = coset::sig_structure_data(
    //     coset::SignatureContext::CoseSign1,
    //     recovered_ocp_cwt.protected.clone(),
    //     None,
    //     &[],
    //     &payload,
    // );

    // if !verify_signature(&recovered_ocp_cwt.signature, pubkey_x, pubkey_y, &message).await {
    //     println!("Signature verification failed");
    //     test_exit(1);
    // }
}

// fn verify_protected_header(protected: &Header) -> bool {
//     if protected.alg
//         != Some(coset::RegisteredLabelWithPrivate::Assigned(
//             Algorithm::ESP384,
//         ))
//     {
//         println!("Unexpected algorithm in protected header");
//         return false;
//     }

//     if protected.content_type
//         != Some(coset::RegisteredLabel::Assigned(
//             coset::iana::CoapContentFormat::EatCwt,
//         ))
//     {
//         println!("Content format mismatch in protected header");
//         return false;
//     }

//     if protected.key_id != OCP_EAT_CLAIMS_KEY_ID.as_bytes().to_vec() {
//         println!("Key ID mismatch in protected header");
//         return false;
//     }

//     true
// }

// async fn verify_unprotected_header(unprotected: &Header, expected_cert: &[u8]) -> bool {
//     let cert_bytes = unprotected.rest.iter().find_map(|(k, v)| {
//         if *k == coset::Label::Int(33) {
//             if let Value::Bytes(ref bytes) = v {
//                 Some(bytes)
//             } else {
//                 None
//             }
//         } else {
//             None
//         }
//     });

//     let cert_bytes = match cert_bytes {
//         Some(bytes) => bytes,
//         None => {
//             println!("X5Chain not found in unprotected header");
//             return false;
//         }
//     };

//     if cert_bytes != expected_cert {
//         println!("Certificate in unprotected header does not match expected certificate");
//         return false;
//     }

//     true
// }

// async fn verify_signature(
//     signature: &[u8],
//     pubkey_x: [u8; 48],
//     pubkey_y: [u8; 48],
//     message: &[u8],
// ) -> bool {
//     if signature.len() != ECC_P384_SIGNATURE_SIZE {
//         println!(
//             "Invalid signature length: expected 96, got {}",
//             signature.len()
//         );
//         return false;
//     }
//     let signature: &[u8; ECC_P384_SIGNATURE_SIZE] = match signature.try_into() {
//         Ok(sig) => sig,
//         Err(_) => {
//             println!("Failed to convert signature slice to array");
//             return false;
//         }
//     };

//     match Ecdsa::ecdsa_verify(pubkey_x, pubkey_y, signature, message).await {
//         Ok(_) => true,
//         Err(err) => {
//             println!("Signature verification failed: {:?}", err);
//             false
//         }
//     }
// }
