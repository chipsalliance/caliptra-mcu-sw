// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{GetLdevCertResp, GetLdevMldsa87CertReq, Request};
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_romtime::{println, test_exit};
use caliptra_mcu_scratch_alloc::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use core::ptr::NonNull;
use mcu_caliptra_api::{
    dpe_certify_key_cert_size, dpe_certify_key_cert_slice, dpe_get_cert_chain_chunk,
    dpe_sign_ecc_p384, get_attested_csr_ecc384, get_attested_csr_mldsa87, get_idev_csr_ecc384,
    get_idev_csr_mldsa87, mldsa87_cert_der_len, populate_idev_ecc384_cert,
    populate_idev_mldsa87_cert, DpeProfile, DPE_LABEL_LEN, DPE_MAX_CHUNK_SIZE,
    DPE_P384_SIGNATURE_SIZE, IDEV_MLDSA87_CSR_MAX_SIZE, IDEV_MLDSA87_CSR_RSP_BUF_SIZE,
};
use zerocopy::{FromBytes, IntoBytes};

const OTP_IDEVID_MLDSA_PARTITION: u32 = 0x02;
const CERT_SCRATCH_SIZE: usize = 16 * 1024;
const CERT_SCRATCH_SLOTS: usize = CERT_SCRATCH_SIZE / BITMAP_SLOT_SIZE;
const MAX_ATTESTED_CSR_SIZE: usize = 12_812;
const TEST_KEY_LABEL: [u8; DPE_LABEL_LEN] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct CertScratchSlot([u8; BITMAP_SLOT_SIZE]);

static CERT_ALLOCATOR: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
static mut CERT_SCRATCH: [CertScratchSlot; CERT_SCRATCH_SLOTS] =
    [CertScratchSlot([0; BITMAP_SLOT_SIZE]); CERT_SCRATCH_SLOTS];
static mut ATTESTED_CSR_BUFFER: [u8; MAX_ATTESTED_CSR_SIZE] = [0; MAX_ATTESTED_CSR_SIZE];

pub fn init_cert_allocator() -> &'static BitmapAllocator {
    let scratch_ptr =
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!(CERT_SCRATCH).cast::<u8>()) };
    unsafe { CERT_ALLOCATOR.init_once(scratch_ptr, CERT_SCRATCH_SIZE) }
}

pub async fn test_get_idev_csr_ecc384() {
    let csr = unsafe { &mut ATTESTED_CSR_BUFFER };
    let size = get_idev_csr_ecc384(csr)
        .await
        .unwrap_or_else(|_| test_exit(1))
        .unwrap_or_else(|| test_exit(1));
    if size == 0 {
        test_exit(1);
    }
    println!("IDevID CSR size: {}", size);
    dump_der_hex("ECC384 IDEVID CSR", &csr[..size]);
}

/// Dump DER as hexadecimal for offline processing.
fn dump_der_hex(label: &str, der: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    println!("---BEGIN {} ({} bytes)---", label, der.len());
    for line in der.chunks(32) {
        let mut buf = [0u8; 64];
        for (i, byte) in line.iter().enumerate() {
            buf[i * 2] = HEX[(byte >> 4) as usize];
            buf[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
        println!("{}", core::str::from_utf8(&buf[..line.len() * 2]).unwrap());
    }
    println!("---END {}---", label);
}

/// Fetch the ML-DSA-87 IDevID CSR from Caliptra and dump it as hex.
///
/// This is the extraction step for the ML-DSA test PKI: the dumped CSR is
/// signed offline by a test root CA to produce the IDevID certificate that
/// gets seeded into the emulated OTP.
///
/// Caliptra only generates an IDevID CSR when the manufacturing flag
/// `mfg_flag_gen_idev_id_csr` was set at cold boot. The integration test does
/// this by selecting `DeviceLifecycle::Manufacturing`, so an absent CSR is a
/// test failure.
pub async fn test_get_idev_csr_mldsa87() {
    let buf = unsafe { &mut ATTESTED_CSR_BUFFER };
    // The response buffer must hold the mailbox response prefix as well as the
    // CSR itself.
    if buf.len() < IDEV_MLDSA87_CSR_RSP_BUF_SIZE {
        test_exit(1);
    }

    let size = get_idev_csr_mldsa87(buf)
        .await
        .unwrap_or_else(|_| test_exit(1))
        .unwrap_or_else(|| test_exit(1));
    if size == 0 || size > IDEV_MLDSA87_CSR_MAX_SIZE {
        test_exit(1);
    }
    println!("IDevID ML-DSA-87 CSR size: {}", size);
    dump_der_hex("MLDSA87 IDEVID CSR", &buf[..size]);
}

/// Fetch the ML-DSA-87 LDevID certificate and validate its response size.
pub async fn test_get_ldev_cert_mldsa87() {
    let buf = unsafe { &mut ATTESTED_CSR_BUFFER };
    let response_len = core::mem::size_of::<GetLdevCertResp>();
    if buf.len() < response_len {
        test_exit(1);
    }

    let mailbox = Mailbox::new();
    let mut req = GetLdevMldsa87CertReq::default();
    let actual = execute_mailbox_cmd(
        &mailbox,
        GetLdevMldsa87CertReq::ID.0,
        req.as_mut_bytes(),
        buf,
    )
    .await
    .unwrap_or_else(|_| test_exit(1));
    let resp =
        GetLdevCertResp::ref_from_bytes(&buf[..response_len]).unwrap_or_else(|_| test_exit(1));
    let size = resp.data_size as usize;
    let prefix_len = core::mem::offset_of!(GetLdevCertResp, data);
    if size == 0 || size > resp.data.len() || prefix_len + size > actual {
        test_exit(1);
    }
    println!("LDevID ML-DSA-87 certificate size: {}", size);
}

/// Read the provisioned ML-DSA-87 IDevID certificate from OTP and install it
/// into Caliptra.
pub async fn populate_idevid_cert_mldsa87_from_otp(alloc: &BitmapAllocator) {
    let otp = ExternalOtp::<DefaultSyscalls>::new();
    let partition_size = otp
        .partition_size(OTP_IDEVID_MLDSA_PARTITION)
        .unwrap_or_else(|_| test_exit(1)) as usize;
    let first_word = otp
        .read(OTP_IDEVID_MLDSA_PARTITION, 0)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let size = mldsa87_cert_der_len(first_word, partition_size).unwrap_or_else(|| test_exit(1));

    let buf = unsafe { &mut ATTESTED_CSR_BUFFER };
    if size > buf.len() {
        test_exit(1);
    }
    for offset in (0..size).step_by(4) {
        let word = otp
            .read(OTP_IDEVID_MLDSA_PARTITION, offset as u32)
            .await
            .unwrap_or_else(|_| test_exit(1))
            .to_le_bytes();
        let end = (offset + word.len()).min(size);
        buf[offset..end].copy_from_slice(&word[..end - offset]);
    }
    populate_idev_mldsa87_cert(alloc, &buf[..size])
        .await
        .unwrap_or_else(|_| test_exit(1));
    println!("Populate IDevID ML-DSA-87 certificate completed successfully");
}

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

pub async fn test_populate_idev_ecc384_cert(alloc: &BitmapAllocator) {
    populate_idev_ecc384_cert(alloc, &SIGNED_IDEV_CERT_DER)
        .await
        .unwrap_or_else(|_| test_exit(1));
    println!("Populate IDev ECC-384 certificate test completed successfully");
}

pub async fn test_get_cert_chain(alloc: &BitmapAllocator) {
    for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
        let mut chunk = [0u8; DPE_MAX_CHUNK_SIZE];
        let mut offset = 0u32;
        loop {
            let size = dpe_get_cert_chain_chunk(alloc, profile, offset, &mut chunk)
                .await
                .unwrap_or_else(|_| test_exit(1));
            offset += size as u32;
            if size < chunk.len() {
                break;
            }
        }
        if offset == 0 {
            test_exit(1);
        }
        println!("Certificate chain size for {:?}: {}", profile, offset);
    }
}

pub async fn test_certify_key(alloc: &BitmapAllocator) {
    for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
        let (_, size) = dpe_certify_key_cert_size(alloc, profile, None, &TEST_KEY_LABEL)
            .await
            .unwrap_or_else(|_| test_exit(1));
        if size == 0 {
            test_exit(1);
        }
        let mut chunk = [0u8; DPE_MAX_CHUNK_SIZE];
        let mut offset = 0;
        while offset < size {
            let requested = (size - offset).min(chunk.len());
            let (_, copied) = dpe_certify_key_cert_slice(
                alloc,
                profile,
                None,
                &TEST_KEY_LABEL,
                offset as u32,
                &mut chunk[..requested],
            )
            .await
            .unwrap_or_else(|_| test_exit(1));
            if copied == 0 || copied > requested {
                test_exit(1);
            }
            offset += copied;
        }
        if offset != size {
            test_exit(1);
        }
        println!(
            "Attestation key certificate size for {:?}: {}",
            profile, size
        );
    }
}

pub async fn test_sign_with_test_key(alloc: &BitmapAllocator) {
    let mut signature = [0u8; DPE_P384_SIGNATURE_SIZE];
    let (_, size) = dpe_sign_ecc_p384(
        alloc,
        None,
        &TEST_KEY_LABEL,
        &[0x5a; DPE_LABEL_LEN],
        &mut signature,
    )
    .await
    .unwrap_or_else(|_| test_exit(1));
    if size != DPE_P384_SIGNATURE_SIZE {
        test_exit(1);
    }
    println!("Attestation key signing test completed successfully");
}

const TEST_NONCE: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

pub async fn test_get_attested_csr() {
    for key_id in [0x0001, 0x0002, 0x0003] {
        let csr = unsafe { &mut ATTESTED_CSR_BUFFER };
        let ecc_size = get_attested_csr_ecc384(key_id, &TEST_NONCE, csr)
            .await
            .unwrap_or_else(|_| test_exit(1));
        if ecc_size == 0 {
            test_exit(1);
        }
        let mldsa_size = get_attested_csr_mldsa87(key_id, &TEST_NONCE, csr)
            .await
            .unwrap_or_else(|_| test_exit(1));
        if mldsa_size == 0 {
            test_exit(1);
        }
        println!(
            "Attested CSR sizes for key {}: {}, {}",
            key_id, ecc_size, mldsa_size
        );
    }
}
