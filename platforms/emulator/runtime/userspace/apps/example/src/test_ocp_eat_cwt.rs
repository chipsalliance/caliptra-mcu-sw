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
}
