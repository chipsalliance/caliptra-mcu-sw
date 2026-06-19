// Licensed under the Apache-2.0 license

extern crate alloc;

mod slot0;

use crate::spdm::cert_store::cert_chain::EndorsementCertChainTrait;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libapi_caliptra::certificate::CertContext;
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
use caliptra_mcu_libsyscall_caliptra::external_otp::ExternalOtp;
use caliptra_mcu_libsyscall_caliptra::mailbox::PayloadStream;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_spdm_lib::cert_store::{CertStoreError, CertStoreResult};

// Example implementation of Endorsement cert chain
pub struct EndorsementCertChain<'b> {
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    root_cert_chain: &'b [&'b [u8]],
    root_cert_chain_len: usize,
}

fn init_endorsement_cert_chain(slot_id: u8) -> CertStoreResult<&'static [&'static [u8]]> {
    match slot_id {
        0 => Ok(slot0::SLOT0_ECC_ROOT_CERT_CHAIN),
        _ => Err(CertStoreError::InvalidSlotId),
    }
}

async fn populate_idev_cert() -> CertStoreResult<()> {
    // Read ECC DevID certificate from external OTP partition 1.
    const ECC_DEVID_CERT_SIZE: usize = 547;
    let mut cert_buf = [0u8; ECC_DEVID_CERT_SIZE];
    let otp = ExternalOtp::<DefaultSyscalls>::new();
    let mut offset = 0u32;
    while offset + 4 <= ECC_DEVID_CERT_SIZE as u32 {
        let word = otp
            .read(0x01, offset)
            .await
            .map_err(|_| CertStoreError::CertReadError)?;
        // Panic-free word store: fixed-size array write -> memcpy, no panic.
        let slot = cert_buf
            .get_mut(offset as usize..)
            .and_then(|s| s.first_chunk_mut::<4>())
            .ok_or(CertStoreError::CertReadError)?;
        *slot = word.to_le_bytes();
        offset += 4;
    }
    // Handle remaining 3 bytes (547 % 4 == 3).
    if (offset as usize) < ECC_DEVID_CERT_SIZE {
        let tail_offset = ECC_DEVID_CERT_SIZE as u32 - 4;
        let word = otp
            .read(0x01, tail_offset)
            .await
            .map_err(|_| CertStoreError::CertReadError)?;
        let word_bytes = word.to_le_bytes();
        let skip = (offset - tail_offset) as usize;
        // Panic-free tail store: copy word_bytes[skip..] without indexing.
        for (d, s) in cert_buf
            .iter_mut()
            .skip(tail_offset as usize + skip)
            .zip(word_bytes.iter().skip(skip))
        {
            *d = *s;
        }
    }

    let mut cert_ctx = CertContext::new();

    while let Err(e) = cert_ctx.populate_idev_ecc384_cert(&cert_buf).await {
        match e {
            CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
            _ => Err(CertStoreError::CaliptraApi(e))?,
        }
    }

    Ok(())
}

#[allow(unused)]
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
            // Fixed-size array write -> memcpy, no panic.
            if let Some(slot) = buffer.get_mut(written..).and_then(|s| s.first_chunk_mut::<4>()) {
                *slot = word.to_le_bytes();
            }
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
            let n = tail_len.min(buffer.len().saturating_sub(written));
            for (d, s) in buffer.iter_mut().skip(written).zip(word_bytes.iter().take(n)) {
                *d = *s;
            }
            written += n;
            self.cursor += n;
        }

        Ok(written)
    }
}

#[allow(unused)]
async fn populate_idev_mldsa_cert() -> CertStoreResult<()> {
    const MLDSA_CERT_SIZE: usize = 4627;
    let mut stream = OtpPayloadStream::new(0x02, MLDSA_CERT_SIZE);

    let bytesum = stream
        .get_bytesum()
        .await
        .map_err(|_| CertStoreError::CertReadError)?;

    let mut cert_ctx = CertContext::new();

    while let Err(e) = cert_ctx
        .populate_idev_mldsa87_cert(MLDSA_CERT_SIZE, bytesum, &mut stream)
        .await
    {
        match e {
            CaliptraApiError::MailboxBusy => {
                stream.reset();
                continue;
            }
            _ => Err(CertStoreError::CaliptraApi(e))?,
        }
    }

    Ok(())
}

impl EndorsementCertChain<'_> {
    pub async fn new(slot_id: u8) -> CertStoreResult<Self> {
        if slot_id == 0 {
            // populate signed idev certs into the device.
            populate_idev_cert().await?;
        }

        let root_cert_chain = init_endorsement_cert_chain(slot_id)?;
        if root_cert_chain.is_empty() {
            return Err(CertStoreError::UnprovisionedSlot);
        }

        let mut root_cert_chain_len = 0;
        for cert in root_cert_chain.iter() {
            root_cert_chain_len += cert.len();
        }

        let mut root_hash = [0; SHA384_HASH_SIZE];
        while let Err(e) =
            HashContext::hash_all(HashAlgoType::SHA384, root_cert_chain[0], &mut root_hash).await
        {
            match e {
                CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
                _ => Err(CertStoreError::CaliptraApi(e))?,
            }
        }
        Ok(Self {
            root_cert_hash: root_hash,
            root_cert_chain,
            root_cert_chain_len,
        })
    }
}

#[async_trait]
impl EndorsementCertChainTrait for EndorsementCertChain<'_> {
    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        root_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        // Equal fixed-size arrays: a direct copy lowers to memcpy, no panic.
        *root_hash = self.root_cert_hash;
        Ok(())
    }

    async fn refresh(&mut self) {
        // No-op for endorsement certs, as they are static
    }

    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        Ok(self.root_cert_chain_len)
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }

        let mut cert_offset = offset;
        let mut pos = 0;

        for cert in self.root_cert_chain.iter() {
            if cert_offset < cert.len() {
                let len = cert
                    .len()
                    .saturating_sub(cert_offset)
                    .min(buf.len().saturating_sub(pos));
                if let (Some(dst), Some(src)) = (
                    buf.get_mut(pos..pos + len),
                    cert.get(cert_offset..cert_offset + len),
                ) {
                    for (d, s) in dst.iter_mut().zip(src.iter()) {
                        *d = *s;
                    }
                }
                pos += len;
                cert_offset = 0; // Reset offset for subsequent certs
                if pos == buf.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        Ok(pos)
    }
}
