// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::CmKeyUsage;
use caliptra_api::mailbox::Cmk;
use libapi_caliptra::certificate::{CertContext, KEY_LABEL_SIZE};
use libapi_caliptra::crypto::aes_gcm::AesGcm;
use libapi_caliptra::crypto::asym::{
    ecdh::Ecdh, ecdsa::Ecdsa, ECC_P384_PARAM_X_SIZE, ECC_P384_PARAM_Y_SIZE, ECC_P384_SIGNATURE_SIZE,
};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::crypto::hmac::{HkdfSalt, Hmac};
use libapi_caliptra::crypto::import::Import;
use libapi_caliptra::crypto::rng::Rng;
use libapi_caliptra::mailbox_api::{MAX_RANDOM_NUM_SIZE, MAX_RANDOM_STIR_SIZE};

use romtime::{println, test_exit, HexBytes};

const EXPECTED_HASHES_384: [[u8; 48]; 1] = [[
    // data 1
    0x95, 0x07, 0x7f, 0x78, 0x7b, 0x9a, 0xe1, 0x93, 0x72, 0x24, 0x54, 0xbe, 0x37, 0xf5, 0x01, 0x2a,
    0x0e, 0xbf, 0x81, 0xd0, 0xe3, 0x99, 0xdc, 0x3f, 0x14, 0x7d, 0x41, 0x31, 0xc3, 0x76, 0x42, 0x7b,
    0xa4, 0x8d, 0xd1, 0xc4, 0xae, 0x71, 0xde, 0x9a, 0x88, 0x54, 0x71, 0x30, 0xf2, 0xc5, 0x04, 0x28,
]];

const EXPECTED_HASHES_512: [[u8; 64]; 1] = [[
    // data 1
    0xd7, 0x71, 0xd8, 0x3e, 0x23, 0xfa, 0xfc, 0x4b, 0x92, 0x67, 0xe1, 0xd5, 0xd8, 0x62, 0x10, 0x6d,
    0x3e, 0xc1, 0x23, 0x26, 0x51, 0x96, 0x45, 0xc8, 0xab, 0x7a, 0xba, 0x26, 0xa5, 0xdf, 0x2e, 0xfd,
    0xcf, 0xda, 0x46, 0x2b, 0x92, 0xc5, 0x3f, 0xab, 0x06, 0x6a, 0x88, 0xf5, 0x06, 0xec, 0x95, 0xd5,
    0x11, 0xd8, 0x0d, 0x6b, 0x05, 0x67, 0x77, 0xd8, 0x36, 0x13, 0x2f, 0x46, 0x9f, 0x6c, 0x68, 0xd3,
]];

pub async fn test_caliptra_sha() {
    println!("Starting Caliptra mailbox SHA test");

    let data1 = b"Hello from Caliptra! This is a test of the SHA algorithm.";
    let expected_sha_384 = EXPECTED_HASHES_384[0];
    let expected_sha_512 = EXPECTED_HASHES_512[0];

    test_sha(data1, HashAlgoType::SHA384, &expected_sha_384).await;
    test_sha(data1, HashAlgoType::SHA512, &expected_sha_512).await;

    println!("SHA test completed successfully");
}

async fn test_sha(data: &[u8], algo: HashAlgoType, expected_hash: &[u8]) {
    println!("Testing SHA algorithm: {:?}", algo);

    let hash_size = algo.hash_size();
    let mut hash_context = HashContext::new();

    let mut hash = [0u8; 64];

    let _ = hash_context.init(algo, None).await.map_err(|e| {
        println!("Failed to initialize hash context with error: {:?}", e);
        test_exit(1);
    });

    let _ = hash_context.update(&data).await.map_err(|e| {
        println!("Failed to update hash context with error: {:?}", e);
        test_exit(1);
    });

    let _ = hash_context.finalize(&mut hash).await.map_err(|e| {
        println!("Failed to finalize hash context with error: {:?}", e);
        test_exit(1);
    });

    if hash[..hash_size] != expected_hash[..] {
        println!(
            "Hash mismatch: expected {:x?}, got {:x?}",
            expected_hash, hash
        );
        test_exit(1);
    }

    println!("SHA test for {:?} passed", algo);
}

pub async fn test_caliptra_rng() {
    println!("Starting Caliptra mailbox RNG test");
    // test_add_random_stir().await;
    test_generate_random_number().await;
    println!("RNG test completed successfully");
}

#[allow(unused)]
async fn test_add_random_stir() {
    println!("Testing RNG add stir");

    let random_stir = [1u8; MAX_RANDOM_STIR_SIZE];

    // Add random stir of max allowed size
    let result = Rng::add_random_stir(&random_stir).await;

    if result.is_err() {
        println!("Failed to add random stir: {:?}", result);
        test_exit(1);
    }

    println!(
        "Random stir of size {} added successfully: {:?}",
        random_stir.len(),
        random_stir
    );
}

async fn test_generate_random_number() {
    println!("Testing RNG");

    let mut random_number = [0u8; MAX_RANDOM_NUM_SIZE];

    // Generate random number of max allowed size
    let result = Rng::generate_random_number(&mut random_number).await;

    if result.is_err() {
        println!("Failed to generate random number: {:?}", result);
        test_exit(1);
    }

    println!(
        "Random number of size {} generated successfully: {:?}",
        random_number.len(),
        random_number
    );

    // Generate random number of size 0
    let result = Rng::generate_random_number(&mut []).await;
    if result.is_err() {
        println!("Failed to generate random number of size 0: {:?}", result);
        test_exit(1);
    }

    println!("Random number of size 0 generated successfully");

    random_number.fill(0);

    // Generate random number of size 1
    let result = Rng::generate_random_number(&mut random_number[..1]).await;
    if result.is_err() {
        println!("Failed to generate random number of size 1: {:?}", result);
        test_exit(1);
    }
    println!(
        "Random number of size 1 generated successfully: {:?}",
        random_number
    );

    // Generate random number of size less than max size
    random_number.fill(0);
    let result = Rng::generate_random_number(&mut random_number[..(MAX_RANDOM_NUM_SIZE - 1)]).await;
    if result.is_err() {
        println!("Failed to generate random number of size 31: {:?}", result);
        test_exit(1);
    }
    println!(
        "Random number of size 31 generated successfully: {:?}",
        random_number
    );
    // Generate random number of size greater than max size
    let mut invalid_random_number = [0u8; MAX_RANDOM_NUM_SIZE + 1];
    let result = Rng::generate_random_number(&mut invalid_random_number).await;
    if !result.is_err() {
        println!("Failed!!. Generate random number of size 33: {:?}", result);
        test_exit(1);
    }
    println!(
        "Generate random number of size 33 failed as expected: {:?}",
        result
    );
}

pub async fn test_caliptra_ecdh() {
    println!("Starting Caliptra mailbox ECDH test");
    test_ecdh().await;
    println!("ECDH test completed successfully");
}

async fn test_ecdh() {
    println!("Testing ECDH");

    let exch1 = Ecdh::ecdh_generate().await.unwrap_or_else(|e| {
        println!("Failed to generate ECDH exchange: {:?}", e);
        test_exit(1);
    });
    let exch2 = Ecdh::ecdh_generate().await.unwrap_or_else(|e| {
        println!("Failed to generate ECDH exchange: {:?}", e);
        test_exit(1);
    });

    let finish = Ecdh::ecdh_finish(CmKeyUsage::Hmac, &exch1, &exch2.exchange_data)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to finish ECDH exchange: {:?}", e);
            test_exit(1);
        });

    let hmac = Hmac::hmac(&finish, &[1, 2, 3, 4])
        .await
        .unwrap_or_else(|e| {
            println!("Failed to compute HMAC: {:?}", e);
            test_exit(1);
        });

    println!("HMAC computed successfully: {}", HexBytes(&hmac.mac[..48]));
    // We don't have a great way to verify the HMAC is correct since Caliptra is our source of
    // truth, and we can't independently verify it from the shared key without pulling in a no_std crypto library.
    println!("ECDH test passed successfully");
}

pub async fn test_caliptra_hmac() {
    println!("Starting Caliptra mailbox HMAC test");
    test_hmac().await;
    println!("HMAC test completed successfully");
}

async fn test_hmac() {
    println!("Testing HMAC");

    let num = [0u8; 48];
    let cmk = Import::import(CmKeyUsage::Hmac, &num)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to import key: {:?}", e);
            test_exit(1);
        })
        .cmk;

    let hmac = Hmac::hmac(&cmk, &num).await.unwrap_or_else(|e| {
        println!("Failed to HMAC: {:?}", e);
        test_exit(1);
    });

    let expected: [u8; 48] = [
        0x7e, 0xe8, 0x20, 0x6f, 0x55, 0x70, 0x02, 0x3e, 0x6d, 0xc7, 0x51, 0x9e, 0xb1, 0x07, 0x3b,
        0xc4, 0xe7, 0x91, 0xad, 0x37, 0xb5, 0xc3, 0x82, 0xaa, 0x10, 0xba, 0x18, 0xe2, 0x35, 0x7e,
        0x71, 0x69, 0x71, 0xf9, 0x36, 0x2f, 0x2c, 0x2f, 0xe2, 0xa7, 0x6b, 0xfd, 0x78, 0xdf, 0xec,
        0x4e, 0xa9, 0xb5,
    ];

    if &hmac.mac[..48] != expected {
        println!(
            "HMAC mismatch: expected {}, got {}",
            HexBytes(&expected),
            HexBytes(&hmac.mac)
        );
        test_exit(1);
    }

    let extract = Hmac::hkdf_extract(HkdfSalt::Data(&num), &cmk)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to HKDF-Extract: {:?}", e);
            test_exit(1);
        });

    let expand = Hmac::hkdf_expand(&extract.prk, CmKeyUsage::Hmac, 48, &num)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to HKDF-Expand: {:?}", e);
            test_exit(1);
        });
    let hmac = Hmac::hmac(&expand.okm, &num).await.unwrap_or_else(|e| {
        println!("Failed to HMAC: {:?}", e);
        test_exit(1);
    });

    let expected: [u8; 48] = [
        0x35, 0xaa, 0x87, 0xc1, 0xc4, 0x4a, 0xee, 0x6c, 0xf4, 0xb3, 0xf7, 0x4d, 0x45, 0xe4, 0xd8,
        0x34, 0x84, 0x48, 0x1b, 0x1c, 0xc8, 0xbc, 0x0c, 0x77, 0x95, 0x1b, 0xac, 0x3f, 0xb9, 0x40,
        0x52, 0x06, 0x1f, 0x38, 0xd2, 0x3d, 0xb0, 0x8e, 0xdf, 0x2d, 0xac, 0xe0, 0x56, 0xb1, 0xbd,
        0xd3, 0x29, 0x49,
    ];

    if &hmac.mac[..48] != expected {
        println!(
            "HMAC mismatch: expected {}, got {}",
            HexBytes(&expected),
            HexBytes(&hmac.mac[..48])
        );
        test_exit(1);
    }

    println!("HMAC test passed successfully");
}

pub async fn test_caliptra_aes_gcm_cipher() {
    let derived_cmk = aes_gcm_keygen_ecdh().await;
    let imported_cmk = aes_gcm_key_import().await;
    let plaintext = b"Caliptra: Secure silicon root of trust powering confidential computing!";
    let mut ciphertext_buf = [0u8; 128]; // Adjust size as needed
    let aad = &[];

    println!("Testing AES-GCM encryption and decryption");
    test_aes_gcm_enc_dec(imported_cmk, aad, &plaintext[..], &mut ciphertext_buf[..]).await;
    test_aes_gcm_enc_dec(derived_cmk, aad, &plaintext[..], &mut ciphertext_buf[..]).await;
    println!("Test AES-GCM encryption and decryption completed successfully");
    println!("Testing AES-GCM SPDM encryption and decryption");
    test_caliptra_aes_gcm_spdm().await;
    println!("Test AES-GCM SPDM encryption and decryption completed successfully");
}

async fn test_aes_gcm_enc_dec(cmk: Cmk, aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) {
    let mut aes_gcm = AesGcm::new();
    let (ciphertext_size, iv, tag) = aes_gcm
        .encrypt(cmk.clone(), aad, plaintext, &mut ciphertext[..])
        .await
        .unwrap_or_else(|e| {
            println!("Failed to encrypt data: {:?}", e);
            test_exit(1);
        });

    // Decrypt the ciphertext using the new decrypt API
    let mut decrypted_plaintext = [0u8; 128]; // Adjust size as needed
    let decrypted_size = aes_gcm
        .decrypt(
            cmk,
            iv,
            aad,
            &ciphertext[..ciphertext_size],
            tag,
            &mut decrypted_plaintext[..],
        )
        .await
        .unwrap_or_else(|e| {
            println!("Failed to decrypt data: {:?}", e);
            test_exit(1);
        });

    assert_eq!(
        &decrypted_plaintext[..decrypted_size],
        &plaintext[..],
        "Decrypted plaintext does not match original plaintext"
    );
}

async fn aes_gcm_keygen_ecdh() -> Cmk {
    let exch1 = Ecdh::ecdh_generate().await.unwrap_or_else(|e| {
        println!("Failed to generate ECDH exchange: {:?}", e);
        test_exit(1);
    });
    let exch2 = Ecdh::ecdh_generate().await.unwrap_or_else(|e| {
        println!("Failed to generate ECDH exchange: {:?}", e);
        test_exit(1);
    });

    let finish_key = Ecdh::ecdh_finish(CmKeyUsage::Aes, &exch1, &exch2.exchange_data)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to finish ECDH exchange: {:?}", e);
            test_exit(1);
        });

    println!("AES-GCM key generated successfully");
    finish_key
}

async fn aes_gcm_key_import() -> Cmk {
    const TEST_AES_GCM_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let cmk = Import::import(CmKeyUsage::Aes, &TEST_AES_GCM_KEY)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to import AES-GCM key: {:?}", e);
            test_exit(1);
        })
        .cmk;
    println!("AES-GCM key imported successfully");
    cmk
}

async fn test_caliptra_aes_gcm_spdm() {
    let num = [8u8; 48];
    let cmk = Import::import(CmKeyUsage::Hmac, &num)
        .await
        .unwrap_or_else(|e| {
            println!("Failed to import key: {:?}", e);
            test_exit(1);
        })
        .cmk;

    let spdm_version = 0x13; // Example SPDM version
    let seq_number = [0u8; 8]; // Example sequence number
    let seq_number_le = true; // Example sequence number endianness
    let aad = b"Example AAD data"; // Example Additional Authenticated Data

    let plaintext = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]; // Example plaintext data

    let mut ciphertext_buf = [0u8; 64]; // Adjust size as needed
    let mut aes_gcm = AesGcm::new();

    let (ciphertext_size, tag) = aes_gcm
        .spdm_message_encrypt(
            cmk.clone(),
            spdm_version,
            seq_number.clone(),
            seq_number_le,
            aad,
            &plaintext[..],
            &mut ciphertext_buf[..],
        )
        .await
        .unwrap_or_else(|e| {
            println!("Failed to SPDM encrypt data: {:?}", e);
            test_exit(1);
        });

    println!(
        "SPDM AES-GCM encryption completed successfully. Ciphertext size: {}, Tag: {}",
        ciphertext_size,
        HexBytes(&tag)
    );

    // Decrypt the ciphertext using the new decrypt API
    let mut decrypted_plaintext = [0u8; 64]; // Adjust size as needed
    let decrypted_size = aes_gcm
        .spdm_message_decrypt(
            cmk,
            spdm_version,
            seq_number,
            seq_number_le,
            aad,
            &ciphertext_buf[..ciphertext_size],
            tag,
            &mut decrypted_plaintext[..],
        )
        .await
        .unwrap_or_else(|e| {
            println!("Failed to SPDM decrypt data: {:?}", e);
            test_exit(1);
        });

    assert_eq!(
        &decrypted_plaintext[..decrypted_size],
        &plaintext[..],
        "Decrypted plaintext does not match original plaintext"
    );
}

pub async fn test_caliptra_ecdsa() {
    println!("Starting Caliptra mailbox ECDSA test");
    test_ecdsa().await;
    println!("ECDSA test completed successfully");
}

async fn test_ecdsa() {
    println!("Testing ECDSA");
    let test_key_label: [u8; KEY_LABEL_SIZE] = [0x44; KEY_LABEL_SIZE];

    let mut cert_ctx = CertContext::new();
    let mut pubkey_x = [0u8; ECC_P384_PARAM_X_SIZE];
    let mut pubkey_y = [0u8; ECC_P384_PARAM_Y_SIZE];
    let mut cert_buf = [0u8; 1024];

    let message: [u8; 128] = [0x55; 128];

    let size = cert_ctx
        .certify_key(
            &mut cert_buf,
            Some(&test_key_label),
            Some(&mut pubkey_x),
            Some(&mut pubkey_y),
        )
        .await
        .map_err(|e| {
            println!("Failed to get DPE leaf cert: {:?}", e);
            test_exit(1);
        })
        .unwrap();

    let mut msg_hash = [0u8; SHA384_HASH_SIZE];
    HashContext::hash_all(HashAlgoType::SHA384, &message, &mut msg_hash)
        .await
        .map_err(|e| {
            println!("Failed to hash message: {:?}", e);
            test_exit(1);
        })
        .unwrap();

    let mut signature = [0u8; ECC_P384_SIGNATURE_SIZE];
    cert_ctx
        .sign(Some(&test_key_label), &msg_hash, &mut signature)
        .await
        .map_err(|e| {
            println!("Failed to sign data: {:?}", e);
            test_exit(1);
        })
        .unwrap();

    match Ecdsa::ecdsa_verify(pubkey_x, pubkey_y, &signature, msg_hash).await {
        Ok(_) => {
            println!("ECDSA signature verified successfully");
        }
        Err(e) => {
            println!("Failed to verify ECDSA signature: {:?}", e);
            test_exit(1);
        }
    }
}
