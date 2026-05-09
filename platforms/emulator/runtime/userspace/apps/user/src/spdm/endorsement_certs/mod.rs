// Licensed under the Apache-2.0 license

extern crate alloc;

mod slot0;

use crate::spdm::cert_store::cert_chain::EndorsementCertChainTrait;
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::certificate::CertContext;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::error::CaliptraApiError;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult};

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
    let mut cert_ctx = CertContext::new();

    while let Err(e) = cert_ctx
        .populate_idev_ecc384_cert(&slot0::SLOT0_ECC_DEVID_CERT_DER)
        .await
    {
        match e {
            CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
            _ => Err(CertStoreError::CaliptraApi(e))?,
        }
    }

    Ok(())
}

impl EndorsementCertChain<'_> {
    pub async fn new(slot_id: u8) -> CertStoreResult<Self> {
        if slot_id == 0 {
            // populate signed idev cert into the device.
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
        root_hash.copy_from_slice(&self.root_cert_hash);
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
                let len = (cert.len() - cert_offset).min(buf.len() - pos);
                buf[pos..pos + len].copy_from_slice(&cert[cert_offset..cert_offset + len]);
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
