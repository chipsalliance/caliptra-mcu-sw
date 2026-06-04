// Licensed under the Apache-2.0 license

//! [`SpdmPalSessionCrypto`] implementation for [`McuSpdmPal`].
//!
//! Thin wrappers over `caliptra-api-lite` ECDH, HKDF, HMAC,
//! AES-GCM, import, and delete functions.

use super::measurements::MeasurementProvider;
use super::*;
use mcu_caliptra_api_lite::{
    cm_delete, cm_hmac, cm_import, ecdh_finish as api_ecdh_finish,
    ecdh_generate as api_ecdh_generate, hkdf_expand, hkdf_extract, spdm_aes_gcm_decrypt,
    spdm_aes_gcm_encrypt, CmKeyUsage, Cmk, HkdfSalt,
};
use mcu_spdm_lite_traits::{McuResult, SpdmPalIo, SpdmPalSessionCrypto};

impl<M: MeasurementProvider> SpdmPalSessionCrypto for McuSpdmPal<M> {
    type Key = Cmk;

    async fn ecdh_generate(&self, _io: &impl SpdmPalIo) -> McuResult<([u8; 76], [u8; 96])> {
        let result = api_ecdh_generate(self).await?;
        Ok((result.context, result.exchange_data))
    }

    async fn ecdh_finish(
        &self,
        _io: &impl SpdmPalIo,
        context: &[u8; 76],
        peer_exchange_data: &[u8; 96],
    ) -> McuResult<Cmk> {
        api_ecdh_finish(self, context, CmKeyUsage::Hmac, peer_exchange_data).await
    }

    async fn hkdf_extract_bytes(
        &self,
        _io: &impl SpdmPalIo,
        salt: &[u8],
        ikm: &Cmk,
    ) -> McuResult<Cmk> {
        hkdf_extract(self, HkdfSalt::Data(salt), ikm).await
    }

    async fn hkdf_extract_key(
        &self,
        _io: &impl SpdmPalIo,
        salt: &Cmk,
        ikm: &Cmk,
    ) -> McuResult<Cmk> {
        hkdf_extract(self, HkdfSalt::Cmk(salt), ikm).await
    }

    async fn hkdf_expand(
        &self,
        _io: &impl SpdmPalIo,
        prk: &Cmk,
        key_size: u32,
        info: &[u8],
    ) -> McuResult<Cmk> {
        hkdf_expand(self, prk, CmKeyUsage::Hmac, key_size, info).await
    }

    async fn hmac(
        &self,
        _io: &impl SpdmPalIo,
        key: &Cmk,
        data: &[u8],
        out: &mut [u8],
    ) -> McuResult<usize> {
        cm_hmac(self, key, data, out).await
    }

    async fn import_key(&self, _io: &impl SpdmPalIo, data: &[u8]) -> McuResult<Cmk> {
        cm_import(self, CmKeyUsage::Hmac, data).await
    }

    async fn delete_key(&self, _io: &impl SpdmPalIo, key: &Cmk) -> McuResult<()> {
        cm_delete(self, key).await
    }

    async fn aead_encrypt(
        &self,
        _io: &impl SpdmPalIo,
        key: &Cmk,
        spdm_version: u8,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> McuResult<(usize, [u8; 16])> {
        let seq_bytes = seq.to_le_bytes();
        spdm_aes_gcm_encrypt(
            self,
            key,
            spdm_version,
            &seq_bytes,
            aad,
            plaintext,
            ciphertext,
        )
        .await
    }

    async fn aead_decrypt(
        &self,
        _io: &impl SpdmPalIo,
        key: &Cmk,
        spdm_version: u8,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> McuResult<usize> {
        let seq_bytes = seq.to_le_bytes();
        spdm_aes_gcm_decrypt(
            self,
            key,
            spdm_version,
            &seq_bytes,
            aad,
            ciphertext,
            tag,
            plaintext,
        )
        .await
    }
}
