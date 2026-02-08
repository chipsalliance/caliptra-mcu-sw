// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Client Library
//!
//! This library provides communication with Caliptra devices using the Mailbox transport
//! abstraction. The UdpTransportDriver implements MailboxDriver to provide UDP-based
//! communication, which is then used through the Mailbox transport layer.

mod network_driver;
pub mod validator;

pub use network_driver::UdpTransportDriver;
pub use validator::{run_basic_validation, run_verbose_validation, ValidationResult, Validator};

// Re-export config from the shared library
pub use caliptra_util_host_mailbox_test_config::*;

use anyhow::Result;
use caliptra_util_host_command_types::crypto_aes::{
    AesMode, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_IV_SIZE,
};
use caliptra_util_host_command_types::crypto_asymmetric::{
    EcdhFinishResponse, EcdhGenerateResponse, EcdsaPublicKeyResponse, EcdsaSignResponse,
    CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, ECC384_SCALAR_BYTE_SIZE,
};
use caliptra_util_host_command_types::crypto_delete::DeleteResponse;
use caliptra_util_host_command_types::crypto_hash::{
    ShaAlgorithm, ShaFinalResponse, ShaInitResponse, ShaUpdateResponse, SHA_CONTEXT_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::{
    CmKeyUsage, Cmk, HmacAlgorithm, HmacKdfCounterResponse, HmacResponse,
};
use caliptra_util_host_command_types::crypto_import::ImportResponse;
use caliptra_util_host_command_types::{
    GetDeviceCapabilitiesResponse, GetDeviceIdResponse, GetDeviceInfoResponse,
    GetFirmwareVersionResponse,
};
use caliptra_util_host_commands::api::crypto_aes::{
    caliptra_aes_decrypt, caliptra_aes_encrypt, caliptra_aes_gcm_decrypt, caliptra_aes_gcm_encrypt,
    AesEncryptResult, AesGcmDecryptResult, AesGcmEncryptResult,
};
use caliptra_util_host_commands::api::crypto_asymmetric::{
    caliptra_cmd_ecdh_finish, caliptra_cmd_ecdh_generate, caliptra_cmd_ecdsa_public_key,
    caliptra_cmd_ecdsa_sign, caliptra_cmd_ecdsa_verify,
};
use caliptra_util_host_commands::api::crypto_delete::caliptra_cmd_delete;
use caliptra_util_host_commands::api::crypto_hash::{
    caliptra_cmd_sha_final, caliptra_cmd_sha_init, caliptra_cmd_sha_update,
};
use caliptra_util_host_commands::api::crypto_hmac::{
    caliptra_cmd_hmac, caliptra_cmd_hmac_kdf_counter,
};
use caliptra_util_host_commands::api::crypto_import::caliptra_cmd_import;
use caliptra_util_host_commands::api::device_info::{
    caliptra_cmd_get_device_capabilities, caliptra_cmd_get_device_id, caliptra_cmd_get_device_info,
    caliptra_cmd_get_firmware_version,
};
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::Mailbox;

/// High-level Mailbox Client for communicating with Caliptra devices
pub struct MailboxClient<'a> {
    transport: Mailbox<'a>,
}

impl<'a> MailboxClient<'a> {
    /// Create a new MailboxClient with the provided mailbox driver
    pub fn new(mailbox_driver: &'a mut dyn caliptra_util_host_transport::MailboxDriver) -> Self {
        let transport = Mailbox::new(mailbox_driver);
        Self { transport }
    }

    /// Create a new MailboxClient with UDP transport
    pub fn with_udp_driver(udp_driver: &'a mut UdpTransportDriver) -> Self {
        let transport =
            Mailbox::new(udp_driver as &mut dyn caliptra_util_host_transport::MailboxDriver);
        Self { transport }
    }

    /// Execute the GetDeviceId command and return the response
    pub fn get_device_id(&mut self) -> Result<GetDeviceIdResponse> {
        println!("Executing GetDeviceId command...");

        // Create session with Mailbox transport
        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        // Connect to the device
        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_id(&mut session) {
            Ok(response) => {
                println!("✓ GetDeviceId succeeded!");
                println!("  Device ID: 0x{:04X}", response.device_id);
                println!("  Vendor ID: 0x{:04X}", response.vendor_id);
                println!(
                    "  Subsystem Vendor ID: 0x{:04X}",
                    response.subsystem_vendor_id
                );
                println!("  Subsystem ID: 0x{:04X}", response.subsystem_id);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceId failed: {:?}", e);
                Err(anyhow::anyhow!("GetDeviceId command failed: {:?}", e))
            }
        }
    }

    /// Validate that the device response matches expected values
    pub fn validate_device_id(
        &mut self,
        expected_device_id: Option<u16>,
        expected_vendor_id: Option<u16>,
    ) -> Result<()> {
        let response = self.get_device_id()?;
        if let Some(expected_id) = expected_device_id {
            if response.device_id != expected_id {
                return Err(anyhow::anyhow!(
                    "Device ID mismatch: got 0x{:04X}, expected 0x{:04X}",
                    response.device_id,
                    expected_id
                ));
            }
            println!("✓ Device ID matches expected value: 0x{:04X}", expected_id);
        }

        if let Some(expected_vendor) = expected_vendor_id {
            if response.vendor_id != expected_vendor {
                return Err(anyhow::anyhow!(
                    "Vendor ID mismatch: got 0x{:04X}, expected 0x{:04X}",
                    response.vendor_id,
                    expected_vendor
                ));
            }
            println!(
                "✓ Vendor ID matches expected value: 0x{:04X}",
                expected_vendor
            );
        }

        Ok(())
    }

    /// Execute the GetDeviceInfo command and return the response
    pub fn get_device_info(&mut self) -> Result<GetDeviceInfoResponse> {
        println!("Executing GetDeviceInfo command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_info(&mut session, 0) {
            Ok(response) => {
                println!("✓ GetDeviceInfo succeeded!");
                println!("  Info length: {} bytes", response.info_length);
                println!("  FIPS status: {}", response.common.fips_status);
                if response.info_length > 0 {
                    let info_str =
                        std::str::from_utf8(&response.info_data[..response.info_length as usize])
                            .unwrap_or("<binary data>");
                    println!("  Info data: {}", info_str);
                }
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceInfo failed: {:?}", e);
                Err(anyhow::anyhow!("GetDeviceInfo command failed: {:?}", e))
            }
        }
    }

    /// Execute the GetDeviceCapabilities command and return the response
    pub fn get_device_capabilities(&mut self) -> Result<GetDeviceCapabilitiesResponse> {
        println!("Executing GetDeviceCapabilities command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_device_capabilities(&mut session) {
            Ok(response) => {
                println!("✓ GetDeviceCapabilities succeeded!");
                println!("  Capabilities: 0x{:08X}", response.capabilities);
                println!("  Max certificate size: {} bytes", response.max_cert_size);
                println!("  Max CSR size: {} bytes", response.max_csr_size);
                println!("  Device lifecycle: {}", response.device_lifecycle);
                println!("  FIPS status: {}", response.common.fips_status);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetDeviceCapabilities failed: {:?}", e);
                Err(anyhow::anyhow!(
                    "GetDeviceCapabilities command failed: {:?}",
                    e
                ))
            }
        }
    }

    /// Execute the GetFirmwareVersion command and return the response
    pub fn get_firmware_version(&mut self, fw_id: u32) -> Result<GetFirmwareVersionResponse> {
        println!("Executing GetFirmwareVersion command (fw_id={})...", fw_id);

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_get_firmware_version(&mut session, fw_id) {
            Ok(response) => {
                println!("✓ GetFirmwareVersion succeeded!");
                println!(
                    "  Version: {}.{}.{}.{}",
                    response.version[0],
                    response.version[1],
                    response.version[2],
                    response.version[3]
                );
                println!("  Git commit hash: {:02X?}", &response.commit_id[..8]);
                println!("  FIPS status: {}", response.common.fips_status);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ GetFirmwareVersion failed: {:?}", e);
                Err(anyhow::anyhow!(
                    "GetFirmwareVersion command failed: {:?}",
                    e
                ))
            }
        }
    }

    /// Execute SHA Init command
    ///
    /// Initializes a SHA hash context with optional initial data.
    pub fn sha_init(&mut self, algorithm: ShaAlgorithm, data: &[u8]) -> Result<ShaInitResponse> {
        println!(
            "Executing SHA Init command (algo={:?}, {} bytes)...",
            algorithm,
            data.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_sha_init(&mut session, algorithm, data) {
            Ok(response) => {
                println!("✓ SHA Init succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ SHA Init failed: {:?}", e);
                Err(anyhow::anyhow!("SHA Init command failed: {:?}", e))
            }
        }
    }

    /// Execute SHA Update command
    ///
    /// Adds more data to an existing hash context.
    pub fn sha_update(
        &mut self,
        context: &[u8; SHA_CONTEXT_SIZE],
        data: &[u8],
    ) -> Result<ShaUpdateResponse> {
        println!("Executing SHA Update command ({} bytes)...", data.len());

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_sha_update(&mut session, context, data) {
            Ok(response) => {
                println!("✓ SHA Update succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ SHA Update failed: {:?}", e);
                Err(anyhow::anyhow!("SHA Update command failed: {:?}", e))
            }
        }
    }

    /// Execute SHA Final command
    ///
    /// Finalizes the hash and returns the result.
    pub fn sha_final(
        &mut self,
        context: &[u8; SHA_CONTEXT_SIZE],
        data: &[u8],
    ) -> Result<ShaFinalResponse> {
        println!(
            "Executing SHA Final command ({} bytes remaining)...",
            data.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_sha_final(&mut session, context, data) {
            Ok(response) => {
                println!("✓ SHA Final succeeded!");
                println!("  Hash size: {} bytes", response.hash_size);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ SHA Final failed: {:?}", e);
                Err(anyhow::anyhow!("SHA Final command failed: {:?}", e))
            }
        }
    }

    /// Compute SHA hash in one operation
    ///
    /// Convenience function that performs init and final in a single call.
    pub fn sha_hash(&mut self, algorithm: ShaAlgorithm, data: &[u8]) -> Result<ShaFinalResponse> {
        println!(
            "Executing SHA one-shot hash (algo={:?}, {} bytes)...",
            algorithm,
            data.len()
        );

        let init_resp = self.sha_init(algorithm, data)?;
        self.sha_final(&init_resp.context, &[])
    }

    /// Execute HMAC command
    ///
    /// Computes HMAC over the provided data using the specified key and algorithm.
    pub fn hmac(
        &mut self,
        cmk: &Cmk,
        algorithm: HmacAlgorithm,
        data: &[u8],
    ) -> Result<HmacResponse> {
        println!(
            "Executing HMAC command (algo={:?}, {} bytes)...",
            algorithm,
            data.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_hmac(&mut session, cmk, algorithm, data) {
            Ok(response) => {
                println!("✓ HMAC succeeded!");
                println!("  MAC size: {} bytes", response.mac_size);
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ HMAC failed: {:?}", e);
                Err(anyhow::anyhow!("HMAC command failed: {:?}", e))
            }
        }
    }

    /// Execute HMAC KDF Counter command
    ///
    /// Derives a key using HMAC-based KDF in counter mode (NIST SP 800-108).
    /// `key_size` is in bytes (e.g., 32 for 256-bit key).
    pub fn hmac_kdf_counter(
        &mut self,
        kin: &Cmk,
        algorithm: HmacAlgorithm,
        key_usage: CmKeyUsage,
        key_size: u32,
        label: &[u8],
    ) -> Result<HmacKdfCounterResponse> {
        println!(
            "Executing HMAC KDF Counter command (algo={:?}, usage={:?}, size={} bytes, label={} bytes)...",
            algorithm,
            key_usage,
            key_size,
            label.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_hmac_kdf_counter(
            &mut session,
            kin,
            algorithm,
            key_usage,
            key_size,
            label,
        ) {
            Ok(response) => {
                println!("✓ HMAC KDF Counter succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ HMAC KDF Counter failed: {:?}", e);
                Err(anyhow::anyhow!("HMAC KDF Counter command failed: {:?}", e))
            }
        }
    }

    /// Execute Import command
    ///
    /// Imports a raw key and returns an encrypted CMK (Cryptographic Mailbox Key)
    /// that can be used for HMAC, HKDF, and other cryptographic operations.
    pub fn import(&mut self, key_usage: CmKeyUsage, key: &[u8]) -> Result<ImportResponse> {
        println!(
            "Executing Import command (usage={:?}, {} bytes)...",
            key_usage,
            key.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_import(&mut session, key_usage, key) {
            Ok(response) => {
                println!("✓ Import succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ Import failed: {:?}", e);
                Err(anyhow::anyhow!("Import command failed: {:?}", e))
            }
        }
    }

    /// Execute Delete command
    ///
    /// Deletes an encrypted CMK from storage. This frees up storage slots
    /// and should be called when a key is no longer needed.
    pub fn delete(&mut self, cmk: &Cmk) -> Result<DeleteResponse> {
        println!("Executing Delete command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_delete(&mut session, cmk) {
            Ok(response) => {
                println!("✓ Delete succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ Delete failed: {:?}", e);
                Err(anyhow::anyhow!("Delete command failed: {:?}", e))
            }
        }
    }

    /// Execute AES encryption
    ///
    /// Encrypts plaintext using AES-CBC or AES-CTR mode.
    pub fn aes_encrypt(
        &mut self,
        cmk: &Cmk,
        mode: AesMode,
        plaintext: &[u8],
    ) -> Result<AesEncryptResult> {
        println!(
            "Executing AES encrypt (mode={:?}, {} bytes)...",
            mode,
            plaintext.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_aes_encrypt(&mut session, cmk, mode, plaintext) {
            Ok(result) => {
                println!(
                    "✓ AES encrypt succeeded! {} bytes ciphertext",
                    result.ciphertext.len()
                );
                Ok(result)
            }
            Err(e) => {
                eprintln!("✗ AES encrypt failed: {:?}", e);
                Err(anyhow::anyhow!("AES encrypt failed: {:?}", e))
            }
        }
    }

    /// Execute AES decryption
    ///
    /// Decrypts ciphertext using AES-CBC or AES-CTR mode.
    pub fn aes_decrypt(
        &mut self,
        cmk: &Cmk,
        mode: AesMode,
        iv: &[u8; AES_IV_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        println!(
            "Executing AES decrypt (mode={:?}, {} bytes)...",
            mode,
            ciphertext.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_aes_decrypt(&mut session, cmk, mode, iv, ciphertext) {
            Ok(plaintext) => {
                println!(
                    "✓ AES decrypt succeeded! {} bytes plaintext",
                    plaintext.len()
                );
                Ok(plaintext)
            }
            Err(e) => {
                eprintln!("✗ AES decrypt failed: {:?}", e);
                Err(anyhow::anyhow!("AES decrypt failed: {:?}", e))
            }
        }
    }

    /// Execute AES-GCM authenticated encryption
    ///
    /// Encrypts plaintext and authenticates both plaintext and AAD.
    pub fn aes_gcm_encrypt(
        &mut self,
        cmk: &Cmk,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<AesGcmEncryptResult> {
        println!(
            "Executing AES-GCM encrypt (aad={} bytes, plaintext={} bytes)...",
            aad.len(),
            plaintext.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_aes_gcm_encrypt(&mut session, cmk, aad, plaintext) {
            Ok(result) => {
                println!(
                    "✓ AES-GCM encrypt succeeded! {} bytes ciphertext",
                    result.ciphertext.len()
                );
                Ok(result)
            }
            Err(e) => {
                eprintln!("✗ AES-GCM encrypt failed: {:?}", e);
                Err(anyhow::anyhow!("AES-GCM encrypt failed: {:?}", e))
            }
        }
    }

    /// Execute AES-GCM authenticated decryption
    ///
    /// Decrypts ciphertext and verifies the authentication tag.
    pub fn aes_gcm_decrypt(
        &mut self,
        cmk: &Cmk,
        iv: &[u8; AES_GCM_IV_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> Result<AesGcmDecryptResult> {
        println!(
            "Executing AES-GCM decrypt (aad={} bytes, ciphertext={} bytes)...",
            aad.len(),
            ciphertext.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_aes_gcm_decrypt(&mut session, cmk, iv, aad, ciphertext, tag) {
            Ok(result) => {
                println!(
                    "✓ AES-GCM decrypt succeeded! tag_verified={}, {} bytes plaintext",
                    result.tag_verified,
                    result.plaintext.len()
                );
                Ok(result)
            }
            Err(e) => {
                eprintln!("✗ AES-GCM decrypt failed: {:?}", e);
                Err(anyhow::anyhow!("AES-GCM decrypt failed: {:?}", e))
            }
        }
    }

    /// Get the public key from an ECDSA CMK
    ///
    /// Extracts the public key (X, Y coordinates) from an encrypted ECDSA CMK.
    pub fn ecdsa_public_key(&mut self, cmk: &Cmk) -> Result<EcdsaPublicKeyResponse> {
        println!("Executing ECDSA public key command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_ecdsa_public_key(&mut session, cmk) {
            Ok(response) => {
                println!("✓ ECDSA public key succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ ECDSA public key failed: {:?}", e);
                Err(anyhow::anyhow!("ECDSA public key command failed: {:?}", e))
            }
        }
    }

    /// Sign a message with an ECDSA CMK
    ///
    /// Signs the provided message using ECDSA-P384.
    pub fn ecdsa_sign(&mut self, cmk: &Cmk, message: &[u8]) -> Result<EcdsaSignResponse> {
        println!("Executing ECDSA sign command ({} bytes)...", message.len());

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_ecdsa_sign(&mut session, cmk, message) {
            Ok(response) => {
                println!("✓ ECDSA sign succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ ECDSA sign failed: {:?}", e);
                Err(anyhow::anyhow!("ECDSA sign command failed: {:?}", e))
            }
        }
    }

    /// Verify an ECDSA signature
    ///
    /// Verifies a signature over a message using the public key derived from the CMK.
    pub fn ecdsa_verify(
        &mut self,
        cmk: &Cmk,
        message: &[u8],
        signature_r: &[u8; ECC384_SCALAR_BYTE_SIZE],
        signature_s: &[u8; ECC384_SCALAR_BYTE_SIZE],
    ) -> Result<()> {
        println!(
            "Executing ECDSA verify command ({} bytes)...",
            message.len()
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_ecdsa_verify(&mut session, cmk, message, signature_r, signature_s) {
            Ok(_) => {
                println!("✓ ECDSA verify succeeded!");
                Ok(())
            }
            Err(e) => {
                eprintln!("✗ ECDSA verify failed: {:?}", e);
                Err(anyhow::anyhow!("ECDSA verify command failed: {:?}", e))
            }
        }
    }

    /// Generate an ephemeral ECDH keypair
    ///
    /// Returns the context (for finish) and exchange data (public key to send to peer).
    pub fn ecdh_generate(&mut self) -> Result<EcdhGenerateResponse> {
        println!("Executing ECDH generate command...");

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_ecdh_generate(&mut session) {
            Ok(response) => {
                println!("✓ ECDH generate succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ ECDH generate failed: {:?}", e);
                Err(anyhow::anyhow!("ECDH generate command failed: {:?}", e))
            }
        }
    }

    /// Complete ECDH key exchange and derive shared secret
    ///
    /// Uses the context from ecdh_generate and the peer's public key to derive a shared CMK.
    pub fn ecdh_finish(
        &mut self,
        context: &[u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
        key_usage: CmKeyUsage,
        incoming_exchange_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
    ) -> Result<EcdhFinishResponse> {
        println!(
            "Executing ECDH finish command (key_usage={:?})...",
            key_usage
        );

        let mut session = CaliptraSession::new(
            1,
            &mut self.transport as &mut dyn caliptra_util_host_transport::Transport,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect to device: {:?}", e))?;

        match caliptra_cmd_ecdh_finish(&mut session, context, key_usage, incoming_exchange_data) {
            Ok(response) => {
                println!("✓ ECDH finish succeeded!");
                Ok(response)
            }
            Err(e) => {
                eprintln!("✗ ECDH finish failed: {:?}", e);
                Err(anyhow::anyhow!("ECDH finish command failed: {:?}", e))
            }
        }
    }
}
