// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libapi_caliptra::certificate::{
    AsymAlgo, CertContext, IDEV_ECC_CSR_MAX_SIZE, KEY_LABEL_SIZE, MAX_ATTESTED_CSR_SIZE,
    MAX_CERT_CHUNK_SIZE, MAX_ECC_CERT_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::mailbox::PayloadStream;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_romtime::println;
use caliptra_mcu_romtime::test_exit;

const TEST_KEY_LABEL: [u8; KEY_LABEL_SIZE] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];

const SIGNED_IDEV_CERT_DER: [u8; 541] = [
    0x30, 0x82, 0x02, 0x19, 0x30, 0x82, 0x01, 0x9f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x5e, 0x31, 0x1a,
    0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x77, 0x77, 0x77, 0x2e, 0x6d, 0x69, 0x63,
    0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43,
    0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x35, 0x30, 0x34, 0x32, 0x39, 0x32, 0x31, 0x32, 0x38, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x34, 0x32, 0x39, 0x32, 0x31, 0x32, 0x38, 0x33, 0x32, 0x5a, 0x30, 0x69, 0x31, 0x1c,
    0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72,
    0x61, 0x20, 0x31, 0x2e, 0x30, 0x20, 0x49, 0x44, 0x65, 0x76, 0x49, 0x44, 0x31, 0x49, 0x30, 0x47,
    0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x40, 0x33, 0x43, 0x35, 0x36, 0x36, 0x46, 0x43, 0x46, 0x35,
    0x46, 0x45, 0x42, 0x42, 0x44, 0x39, 0x44, 0x34, 0x39, 0x35, 0x41, 0x34, 0x33, 0x37, 0x31, 0x43,
    0x38, 0x34, 0x38, 0x30, 0x35, 0x44, 0x31, 0x38, 0x36, 0x44, 0x38, 0x34, 0x31, 0x33, 0x37, 0x30,
    0x41, 0x46, 0x30, 0x36, 0x32, 0x30, 0x39, 0x43, 0x34, 0x33, 0x39, 0x46, 0x30, 0x44, 0x34, 0x44,
    0x32, 0x30, 0x44, 0x41, 0x42, 0x34, 0x35, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x65,
    0x1e, 0x70, 0x12, 0x44, 0xb9, 0x4f, 0x45, 0xc6, 0x55, 0xc8, 0x2d, 0xa4, 0x00, 0xc6, 0x35, 0xc9,
    0x56, 0xa0, 0x7e, 0x24, 0xd6, 0xf6, 0x8a, 0xc0, 0x48, 0xe5, 0x9c, 0xfb, 0x60, 0x96, 0x25, 0xfb,
    0xc4, 0xd4, 0x86, 0xea, 0xa8, 0x16, 0xbe, 0xd2, 0x33, 0x6f, 0xd3, 0xeb, 0x10, 0x0d, 0x4e, 0x0d,
    0x80, 0x6d, 0xe8, 0x8b, 0x09, 0x9c, 0xe9, 0xd6, 0x4f, 0x4d, 0x1d, 0x0b, 0x51, 0x0d, 0x96, 0x57,
    0xd5, 0xa9, 0xe2, 0x4c, 0xe4, 0x81, 0x88, 0xd2, 0xbe, 0x1e, 0x2a, 0xa0, 0xb6, 0xf7, 0xd8, 0x8e,
    0x8e, 0xa1, 0xa5, 0x56, 0x7b, 0x6e, 0x03, 0xe4, 0x12, 0x22, 0x92, 0x57, 0x2d, 0xb1, 0x1b, 0xa3,
    0x26, 0x30, 0x24, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30,
    0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x05, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x56, 0xb1, 0xf0, 0x82, 0x8c, 0x76,
    0xa6, 0x11, 0x81, 0x17, 0x7a, 0x0e, 0x1b, 0x30, 0x52, 0x6f, 0x01, 0xea, 0xf3, 0xcb, 0x3b, 0xae,
    0x4c, 0x78, 0xa0, 0x41, 0x99, 0x79, 0xb8, 0x58, 0x3a, 0xdb, 0xea, 0xcb, 0x90, 0x8d, 0x2c, 0x3e,
    0xc9, 0x09, 0xe8, 0xe7, 0xdc, 0x4a, 0x90, 0x9c, 0xe1, 0xe1, 0x02, 0x31, 0x00, 0xad, 0xa2, 0x53,
    0x91, 0x20, 0x51, 0x16, 0x52, 0x6e, 0x73, 0x05, 0xa5, 0xa9, 0xdf, 0x18, 0x57, 0xab, 0xe3, 0xe7,
    0x51, 0xa5, 0xd1, 0x70, 0xcb, 0x53, 0xfc, 0xec, 0xba, 0x29, 0x69, 0xb3, 0x44, 0xc5, 0x23, 0x3a,
    0xe5, 0x40, 0x6f, 0xa0, 0x49, 0xa9, 0x61, 0x17, 0x38, 0x5f, 0x5a, 0x5c, 0x93,
];

// test get idev_csr
#[inline(never)]
pub async fn test_get_idev_csr() {
    println!("Starting Caliptra mailbox get idev csr test");

    let mut cert_mgr = CertContext::new();
    let mut csr_der = [0u8; IDEV_ECC_CSR_MAX_SIZE];
    let result = cert_mgr.get_idev_csr(&mut csr_der).await;
    match result {
        Ok(size) => {
            println!("Retrieved CSR of size: {}", size);
            if size > IDEV_ECC_CSR_MAX_SIZE {
                println!("CSR retrieval failed: size exceeds maximum");
                test_exit(1);
            }
            if size == 0 {
                println!("CSR retrieval failed: size is zero");
                test_exit(1);
            }

            println!("CSR data: {:?}", &csr_der[..size]);
        }
        Err(e) => {
            println!("Failed to get CSR with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get idev csr test completed successfully");
}

#[inline(never)]
pub async fn test_populate_idev_ecc384_cert() {
    println!("Starting Caliptra mailbox populate idev cert test");

    println!(
        "Populating idev certificate with size: {}",
        SIGNED_IDEV_CERT_DER.len()
    );
    println!("Signed idev certificate data: {:?}", &SIGNED_IDEV_CERT_DER);

    let mut cert_mgr = CertContext::new();
    let result = cert_mgr
        .populate_idev_ecc384_cert(&SIGNED_IDEV_CERT_DER)
        .await;
    match result {
        Ok(_) => {
            println!("Successfully populated idev certificate");
        }
        Err(e) => {
            println!("Failed to populate idev certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Populate idev cert test completed successfully");
}

struct OtpPayloadStream {
    otp: ExternalOtp<DefaultSyscalls>,
    partition_id: u32,
    total_size: usize,
    cursor: usize,
}

impl OtpPayloadStream {
    fn new(partition_id: u32, total_size: usize) -> Self {
        Self {
            otp: ExternalOtp::new(),
            partition_id,
            total_size,
            cursor: 0,
        }
    }

    fn reset(&mut self) {
        self.cursor = 0;
    }

    async fn get_bytesum(&mut self) -> Result<u32, ErrorCode> {
        self.reset();
        let mut sum = 0u32;
        let mut buf = [0u8; 256];
        loop {
            let n = self.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            for b in &buf[..n] {
                sum = sum.wrapping_add(u32::from(*b));
            }
        }
        self.reset();
        Ok(sum)
    }
}

#[async_trait(?Send)]
impl PayloadStream for OtpPayloadStream {
    fn size(&self) -> usize {
        self.total_size
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if self.cursor >= self.total_size || buffer.is_empty() {
            return Ok(0);
        }

        let mut written = 0;

        // Read full words while there's room in the buffer and data in the partition
        while self.cursor + 4 <= self.total_size && written + 4 <= buffer.len() {
            let word = self
                .otp
                .read(self.partition_id, self.cursor as u32)
                .await
                .map_err(|_| ErrorCode::Fail)?;
            buffer[written..written + 4].copy_from_slice(&word.to_le_bytes());
            written += 4;
            self.cursor += 4;
        }

        // Handle tail bytes (remaining bytes < 4)
        if self.cursor < self.total_size && written < buffer.len() {
            let tail_len = self.total_size - self.cursor;
            let word = self
                .otp
                .read(self.partition_id, self.cursor as u32)
                .await
                .map_err(|_| ErrorCode::Fail)?;
            let word_bytes = word.to_le_bytes();
            let n = tail_len.min(buffer.len() - written);
            buffer[written..written + n].copy_from_slice(&word_bytes[..n]);
            written += n;
            self.cursor += n;
        }

        Ok(written)
    }
}

pub async fn test_populate_idev_mldsa87_cert() {
    println!("Starting Caliptra mailbox populate idev MLDSA cert test");

    const MLDSA_CERT_SIZE: usize = 4627;
    let mut stream = OtpPayloadStream::new(0x02, MLDSA_CERT_SIZE);

    let bytesum = match stream.get_bytesum().await {
        Ok(sum) => sum,
        Err(e) => {
            println!("Failed to compute MLDSA cert bytesum: {:?}", e);
            test_exit(1);
            return;
        }
    };

    println!(
        "Populating idev MLDSA certificate with size: {}, bytesum: 0x{:08x}",
        MLDSA_CERT_SIZE, bytesum
    );

    let mut cert_mgr = CertContext::new();
    let result = cert_mgr
        .populate_idev_mldsa87_cert(MLDSA_CERT_SIZE, bytesum, &mut stream)
        .await;
    match result {
        Ok(_) => {
            println!("Successfully populated idev MLDSA certificate");
        }
        Err(e) => {
            println!(
                "Failed to populate idev MLDSA certificate with error: {:?}",
                e
            );
            test_exit(1);
        }
    }
    println!("Populate idev MLDSA cert test completed successfully");
}

#[inline(never)]
pub async fn test_get_ldev_ecc384_cert() {
    println!("Starting Caliptra mailbox get ldev cert test");

    let mut cert_mgr = CertContext::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_ldev_ecc384_cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved LDEV certificate of size: {}", size);

            if size == 0 {
                println!("LDEV certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("LDEV certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get LDEV certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get ldev cert test completed successfully");
}

#[inline(never)]
pub async fn test_get_fmc_alias_ecc384cert() {
    println!("Starting Caliptra mailbox get FMC alias cert test");

    let mut cert_mgr = CertContext::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_fmc_alias_ecc384_cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved FMC alias certificate of size: {}", size);

            if size == 0 {
                println!("FMC alias certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("FMC alias certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get FMC alias certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get FMC alias cert test completed successfully");
}

#[inline(never)]
pub async fn test_get_rt_alias_ecc384cert() {
    println!("Starting Caliptra mailbox get FMC cert test");

    let mut cert_mgr = CertContext::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_rt_alias_384cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved RT alias certificate of size: {}", size);

            if size == 0 {
                println!("RT alias certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("RT alias certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get RT alias certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get RT alias cert test completed successfully");
}

#[inline(never)]
pub async fn test_get_cert_chain() {
    println!("Starting Caliptra mailbox get cert chain test");

    let mut cert_chain = [0u8; 4098];

    let mut cert_mgr = CertContext::new();
    let mut cert_chunk = [0u8; MAX_CERT_CHUNK_SIZE];
    let mut offset = 0;

    let mut cert_chain_complete = false;

    loop {
        if cert_chain_complete {
            break;
        }

        cert_chunk.fill(0);
        println!("Getting certificate chain chunk at offset: {}", offset);

        // Get the next chunk of the certificate chain
        let result = cert_mgr.cert_chain_chunk(offset, &mut cert_chunk).await;
        match result {
            Ok(size) => {
                println!("Retrieved certificate chain of size: {}", size);

                if size < MAX_CERT_CHUNK_SIZE {
                    println!("Certificate chain retrieval completed");
                    cert_chain_complete = true;
                }

                // println!("Certificate chain data: {:?}", &cert_chain[..size]);
                if size > 0 {
                    cert_chain[offset..offset + size].copy_from_slice(&cert_chunk[..size]);
                    offset += size;
                }
            }
            Err(e) => {
                println!("Failed to get certificate chain with error: {:x?}", e);
                test_exit(1);
            }
        }
    }
    println!(
        "Get cert chain test completed successfully. Cert chain size: {}",
        offset
    );
    println!("Cert chain data: {:?}", &cert_chain[..offset]);
}

#[inline(never)]
pub async fn test_certify_key() {
    println!("Starting Caliptra mailbox certify attestation key test");

    let mut cert_mgr = CertContext::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let mut pubkey_x = [0u8; 48];
    let mut pubkey_y = [0u8; 48];
    let result = cert_mgr
        .certify_key(
            &mut cert,
            Some(&TEST_KEY_LABEL),
            Some(&mut pubkey_x),
            Some(&mut pubkey_y),
        )
        .await;
    match result {
        Ok(size) => {
            println!("Retrieved attestation key certificate of size: {}", size);

            if size == 0 {
                println!("Attestation key certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("Attestation key certificate data: {:?}", &cert[..size]);
            println!("Attestation key public key X: {:?}", &pubkey_x[..]);
            println!("Attestation key public key Y: {:?}", &pubkey_y[..]);
        }
        Err(e) => {
            println!(
                "Failed to get attestation key certificate with error: {:?}",
                e
            );
            test_exit(1);
        }
    }

    println!("Certify attestation key test completed successfully");
}

#[inline(never)]
pub async fn test_sign_with_test_key() {
    println!("Starting Caliptra mailbox sign with attestation key test");

    let mut cert_mgr = CertContext::new();
    let test_digest: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30,
    ];
    let mut signature = [0u8; 128];
    let result = cert_mgr
        .sign(Some(&TEST_KEY_LABEL), &test_digest, &mut signature)
        .await;
    match result {
        Ok(size) => {
            println!("Retrieved attestation key signature of size: {}", size);

            if size == 0 {
                println!("Attestation key signature retrieval failed: size is zero");
                test_exit(1);
            }

            println!("Attestation key signature data: {:?}", &signature[..size]);
        }
        Err(e) => {
            println!(
                "Failed to get attestation key signature with error: {:?}",
                e
            );
            test_exit(1);
        }
    }
    println!("Sign with attestation key test completed successfully");
}

// Key IDs for attested CSR requests (matches DeviceKeyId in VDM protocol)
const KEY_ID_LDEVID: u32 = 0x0001;
const KEY_ID_FMC_ALIAS: u32 = 0x0002;
const KEY_ID_RT_ALIAS: u32 = 0x0003;

const TEST_NONCE: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn key_type_name(key_id: u32) -> &'static str {
    match key_id {
        KEY_ID_LDEVID => "LDevID",
        KEY_ID_FMC_ALIAS => "FMC Alias",
        KEY_ID_RT_ALIAS => "RT Alias",
        _ => "Unknown",
    }
}

async fn test_get_attested_csr_for(algo: AsymAlgo, key_id: u32) {
    println!(
        "Starting get attested {:?} CSR test for key: {} (0x{:04x})",
        algo,
        key_type_name(key_id),
        key_id
    );
    let mut cert_mgr = CertContext::new();
    let mut csr_data = [0u8; MAX_ATTESTED_CSR_SIZE];
    match cert_mgr
        .get_attested_csr(algo, key_id, &TEST_NONCE, &mut csr_data)
        .await
    {
        Ok(size) => {
            println!("Retrieved attested {:?} CSR of size: {}", algo, size);
            println!("Attested {:?} CSR data: {:?}", algo, &csr_data[..size]);
        }
        Err(e) => {
            println!("Failed to get attested {:?} CSR: {:?}", algo, e);
            test_exit(1);
        }
    }
    println!("Get attested {:?} CSR test completed successfully", algo);
}

pub async fn test_get_attested_csr() {
    for &key_id in &[KEY_ID_LDEVID, KEY_ID_FMC_ALIAS, KEY_ID_RT_ALIAS] {
        test_get_attested_csr_for(AsymAlgo::EccP384, key_id).await;
        // Test is failing due to caliptra-core stack overflow when processing MLDSA CSR requests,
        // so skipping MLDSA for now until that is resolved.
        // test_get_attested_csr_for(AsymAlgo::MlDsa87, key_id).await;
    }
}
