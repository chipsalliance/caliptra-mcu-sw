// Licensed under the Apache-2.0 license

use caliptra_mcu_romtime::{println, test_exit, HexBytes};
use caliptra_mcu_spdm_pal::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use core::ptr::NonNull;
use mcu_caliptra_api_lite::{
    cm_hmac, cm_import, dpe_certify_key_pubkey, dpe_sign_ecc_p384, ecdh_finish, ecdh_generate,
    hkdf_expand, hkdf_extract, rng_generate, sha_finish, sha_init, sha_update,
    spdm_aes_gcm_decrypt, spdm_aes_gcm_encrypt, CmKeyUsage, HashAlgo, HkdfSalt,
    CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, DPE_LABEL_LEN,
    DPE_P384_SIGNATURE_SIZE, SHA_CONTEXT_SIZE,
};

const CRYPTO_SCRATCH_SIZE: usize = 16 * 1024;
const CRYPTO_SCRATCH_SLOTS: usize = CRYPTO_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct CryptoScratchSlot([u8; BITMAP_SLOT_SIZE]);

static CRYPTO_ALLOCATOR: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
static mut CRYPTO_SCRATCH: [CryptoScratchSlot; CRYPTO_SCRATCH_SLOTS] =
    [CryptoScratchSlot([0; BITMAP_SLOT_SIZE]); CRYPTO_SCRATCH_SLOTS];

pub fn init_crypto_allocator() -> &'static BitmapAllocator {
    let scratch_ptr =
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!(CRYPTO_SCRATCH).cast::<u8>()) };
    unsafe { CRYPTO_ALLOCATOR.init_once(scratch_ptr, CRYPTO_SCRATCH_SIZE) }
}

pub async fn test_caliptra_sha(alloc: &BitmapAllocator) {
    const DATA: &[u8] = b"Hello from Caliptra! This is a test of the SHA algorithm.";
    const SHA384: [u8; 48] = [
        0x95, 0x07, 0x7f, 0x78, 0x7b, 0x9a, 0xe1, 0x93, 0x72, 0x24, 0x54, 0xbe, 0x37, 0xf5, 0x01,
        0x2a, 0x0e, 0xbf, 0x81, 0xd0, 0xe3, 0x99, 0xdc, 0x3f, 0x14, 0x7d, 0x41, 0x31, 0xc3, 0x76,
        0x42, 0x7b, 0xa4, 0x8d, 0xd1, 0xc4, 0xae, 0x71, 0xde, 0x9a, 0x88, 0x54, 0x71, 0x30, 0xf2,
        0xc5, 0x04, 0x28,
    ];
    const SHA512: [u8; 64] = [
        0xd7, 0x71, 0xd8, 0x3e, 0x23, 0xfa, 0xfc, 0x4b, 0x92, 0x67, 0xe1, 0xd5, 0xd8, 0x62, 0x10,
        0x6d, 0x3e, 0xc1, 0x23, 0x26, 0x51, 0x96, 0x45, 0xc8, 0xab, 0x7a, 0xba, 0x26, 0xa5, 0xdf,
        0x2e, 0xfd, 0xcf, 0xda, 0x46, 0x2b, 0x92, 0xc5, 0x3f, 0xab, 0x06, 0x6a, 0x88, 0xf5, 0x06,
        0xec, 0x95, 0xd5, 0x11, 0xd8, 0x0d, 0x6b, 0x05, 0x67, 0x77, 0xd8, 0x36, 0x13, 0x2f, 0x46,
        0x9f, 0x6c, 0x68, 0xd3,
    ];
    test_sha(alloc, DATA, HashAlgo::Sha384, &SHA384).await;
    test_sha(alloc, DATA, HashAlgo::Sha512, &SHA512).await;
    println!("SHA test completed successfully");
}

async fn test_sha(alloc: &BitmapAllocator, data: &[u8], algo: HashAlgo, expected: &[u8]) {
    let context = alloc
        .alloc_bytes(SHA_CONTEXT_SIZE)
        .unwrap_or_else(|_| test_exit(1));
    let mut state = sha_init(alloc, context, algo, &[])
        .await
        .unwrap_or_else(|_| test_exit(1));
    sha_update(alloc, &mut state, data)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let mut digest = [0u8; 64];
    sha_finish(alloc, &mut state, &mut digest[..algo.hash_size()])
        .await
        .unwrap_or_else(|_| test_exit(1));
    if &digest[..algo.hash_size()] != expected {
        test_exit(1);
    }
}

pub async fn test_caliptra_rng(alloc: &BitmapAllocator) {
    let mut random = [0u8; 32];
    rng_generate(alloc, &mut random)
        .await
        .unwrap_or_else(|_| test_exit(1));
    println!("RNG test completed successfully: {:?}", random);
}

async fn make_exchange(
    alloc: &BitmapAllocator,
) -> (
    [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
) {
    let mut context = [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE];
    let mut exchange = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];
    ecdh_generate(alloc, &mut context, &mut exchange)
        .await
        .unwrap_or_else(|_| test_exit(1));
    (context, exchange)
}

pub async fn test_caliptra_ecdh(alloc: &BitmapAllocator) {
    let (context, our_exchange) = make_exchange(alloc).await;
    let (_, peer_exchange) = make_exchange(alloc).await;
    let cmk = ecdh_finish(alloc, &context, CmKeyUsage::Hmac, &peer_exchange)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let mut mac = [0u8; 48];
    cm_hmac(alloc, &cmk, &our_exchange, &mut mac)
        .await
        .unwrap_or_else(|_| test_exit(1));
    println!("ECDH/HMAC test completed successfully: {}", HexBytes(&mac));
}

pub async fn test_caliptra_hmac(alloc: &BitmapAllocator) {
    let data = [0u8; 48];
    let cmk = cm_import(alloc, CmKeyUsage::Hmac, &data)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let prk = hkdf_extract(alloc, HkdfSalt::Data(&data), &cmk)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let okm = hkdf_expand(alloc, &prk, CmKeyUsage::Hmac, 48, &data)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let mut mac = [0u8; 48];
    cm_hmac(alloc, &okm, &data, &mut mac)
        .await
        .unwrap_or_else(|_| test_exit(1));
    println!("HMAC/HKDF test completed successfully: {}", HexBytes(&mac));
}

pub async fn test_caliptra_aes_gcm_cipher(alloc: &BitmapAllocator) {
    let key = cm_import(alloc, CmKeyUsage::Hmac, &[8; 48])
        .await
        .unwrap_or_else(|_| test_exit(1));
    let plaintext = b"Caliptra SPDM AES-GCM lite API";
    let sequence = [0u8; 8];
    let mut ciphertext = [0u8; 64];
    let (len, tag) = spdm_aes_gcm_encrypt(
        alloc,
        &key,
        0x13,
        &sequence,
        b"example aad",
        plaintext,
        &mut ciphertext,
    )
    .await
    .unwrap_or_else(|_| test_exit(1));
    let mut decrypted = [0u8; 64];
    let decrypted_len = spdm_aes_gcm_decrypt(
        alloc,
        &key,
        0x13,
        &sequence,
        b"example aad",
        &ciphertext[..len],
        &tag,
        &mut decrypted,
    )
    .await
    .unwrap_or_else(|_| test_exit(1));
    if &decrypted[..decrypted_len] != plaintext {
        test_exit(1);
    }
    println!("AES-GCM test completed successfully");
}

pub async fn test_caliptra_ecdsa(alloc: &BitmapAllocator) {
    let label = [0x44; DPE_LABEL_LEN];
    let mut pubkey_x = [0u8; 48];
    let mut pubkey_y = [0u8; 48];
    let handle = dpe_certify_key_pubkey(alloc, None, &label, &mut pubkey_x, &mut pubkey_y)
        .await
        .unwrap_or_else(|_| test_exit(1));
    let mut signature = [0u8; DPE_P384_SIGNATURE_SIZE];
    let (_, len) = dpe_sign_ecc_p384(alloc, Some(&handle), &label, &[0x55; 48], &mut signature)
        .await
        .unwrap_or_else(|_| test_exit(1));
    if len != DPE_P384_SIGNATURE_SIZE {
        test_exit(1);
    }
    println!("DPE ECDSA signing test completed successfully");
}
