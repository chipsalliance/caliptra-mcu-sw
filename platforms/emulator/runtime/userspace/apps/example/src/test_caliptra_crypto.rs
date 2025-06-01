// Licensed under the Apache-2.0 license

use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};

use core::fmt::write;
use romtime::{println, test_exit};

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
