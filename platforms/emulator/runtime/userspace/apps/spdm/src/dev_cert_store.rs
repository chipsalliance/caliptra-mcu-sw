// Licensed under the Apache-2.0 license
extern crate alloc;

use crate::config::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::certificate::CertContext;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::error::CaliptraApiError;
use spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, SpdmCertStore, MAX_CERT_SLOTS_SUPPORTED,
};
use spdm_lib::protocol::{
    AsymAlgo, CertificateInfo, KeyUsageMask, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE,
};

#[derive(Debug)]
#[allow(dead_code)]
pub enum DevCertStoreError {
    InvalidSlotId,
    DpeLeafCertError,
    CaliptraApi(CaliptraApiError),
}

pub type DevCertStoreResult<T> = Result<T, DevCertStoreError>;

pub struct DeviceCertStore<'a> {
    pub(crate) cert_chains: [Option<DeviceCertChain<'a>>; MAX_CERT_SLOTS_SUPPORTED as usize],
}

impl<'a> DeviceCertStore<'a> {
    fn cert_chain(&self, slot_id: u8) -> Option<&DeviceCertChain<'a>> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return None;
        }
        self.cert_chains[slot_id as usize].as_ref()
    }

    fn cert_chain_mut(&mut self, slot_id: u8) -> Option<&mut DeviceCertChain<'a>> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return None;
        }
        self.cert_chains[slot_id as usize].as_mut()
    }
}

pub struct CertBuf {
    pub buf: [u8; MAX_CERT_SIZE],
    pub size: usize,
}

pub struct DeviceCertChain<'b> {
    slot_id: u8,
    root_cert_chain: &'b [&'b [u8]],
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    root_cert_chain_len: usize,
    leaf_cert: Option<CertBuf>,
    device_cert_chain_len: Option<usize>,
}

impl<'b> DeviceCertChain<'b> {
    pub async fn new(slot_id: u8) -> DevCertStoreResult<Self> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            Err(DevCertStoreError::InvalidSlotId)?;
        }

        let root_cert_chain =
            ROOT_CERT_CHAINS[slot_id as usize].ok_or(DevCertStoreError::InvalidSlotId)?;

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
                _ => Err(DevCertStoreError::CaliptraApi(e))?,
            }
        }

        if DPE_LEAF_CERT_LABELS[slot_id as usize].is_none() {
            return Err(DevCertStoreError::DpeLeafCertError);
        }

        populate_idev_ecc384_cert(slot_id).await?;

        Ok(Self {
            slot_id,
            root_cert_chain,
            root_cert_hash: root_hash,
            root_cert_chain_len,
            leaf_cert: None,
            device_cert_chain_len: None,
        })
    }

    async fn read_device_ecc_cert_chain(
        &self,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        CertContext::new()
            .cert_chain_chunk(offset, cert_portion)
            .await
            .map_err(CertStoreError::CaliptraApi)
    }

    fn read_root_cert_chain(
        &self,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        let mut cert_offset = offset;
        let mut pos = 0;

        for cert in self.root_cert_chain.iter() {
            if cert_offset < cert.len() {
                let len = (cert.len() - cert_offset).min(cert_portion.len() - pos);
                cert_portion[pos..pos + len].copy_from_slice(&cert[cert_offset..cert_offset + len]);
                pos += len;
                cert_offset = 0; // Reset offset for subsequent certs
                if pos == cert_portion.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        Ok(pos)
    }

    async fn device_certchain_len(&mut self) -> CertStoreResult<usize> {
        let mut cert_chain_len = 0;
        let mut offset = 0;
        loop {
            let size = self
                .read_device_ecc_cert_chain(offset, &mut [0; MAX_CERT_SIZE])
                .await?;
            offset += size;
            if size < MAX_CERT_SIZE {
                cert_chain_len += offset;
                break;
            }
        }
        self.device_cert_chain_len = Some(cert_chain_len);
        Ok(cert_chain_len)
    }

    fn read_dpe_leaf_cert(&self, offset: usize, cert_portion: &mut [u8]) -> CertStoreResult<usize> {
        if let Some(leaf_cert) = self.leaf_cert.as_ref() {
            if offset >= leaf_cert.size {
                Err(CertStoreError::CertReadError)?;
            }
            let len = (leaf_cert.size - offset).min(cert_portion.len());
            cert_portion[..len].copy_from_slice(&leaf_cert.buf[offset..offset + len]);
            Ok(len)
        } else {
            Err(CertStoreError::CertReadError)
        }
    }

    async fn refresh_dpe_leaf_cert(&mut self) -> CertStoreResult<usize> {
        let mut cert_ctx = CertContext::new();
        let mut cert = [0; MAX_CERT_SIZE];
        let label =
            DPE_LEAF_CERT_LABELS[self.slot_id as usize].ok_or(CertStoreError::InvalidSlotId)?;
        let mut key_label = [0; SHA384_HASH_SIZE];
        key_label.copy_from_slice(&label[..SHA384_HASH_SIZE]);

        let size = cert_ctx
            .certify_key(&mut cert, Some(&key_label), None, None)
            .await
            .map_err(CertStoreError::CaliptraApi)?;
        let cert_buf = CertBuf { buf: cert, size };
        self.leaf_cert = Some(cert_buf);
        Ok(size)
    }

    async fn sign_with_leaf_key(
        &self,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let label =
            DPE_LEAF_CERT_LABELS[self.slot_id as usize].ok_or(CertStoreError::InvalidSlotId)?;
        let mut key_label = [0; SHA384_HASH_SIZE];
        key_label.copy_from_slice(&label[..SHA384_HASH_SIZE]);

        let mut cert_ctx = CertContext::new();
        cert_ctx
            .sign(Some(&key_label), hash, signature)
            .await
            .map_err(CertStoreError::CaliptraApi)?;
        Ok(())
    }

    async fn refresh_ecc_cert_chain(&mut self) -> CertStoreResult<(usize, usize, usize)> {
        let root_cert_chain_len = self.root_cert_chain_len;
        let device_cert_chain_len = self.device_certchain_len().await?;
        let dpe_leaf_cert_len = self.refresh_dpe_leaf_cert().await?;
        Ok((
            root_cert_chain_len,
            device_cert_chain_len,
            dpe_leaf_cert_len,
        ))
    }
}

#[async_trait]
impl<'b> SpdmCertStore for DeviceCertStore<'b> {
    fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    fn is_provisioned(&self, slot_id: u8) -> bool {
        if slot_id >= self.slot_count() {
            return false;
        }
        self.cert_chains[slot_id as usize].is_some()
    }

    async fn cert_chain_len(
        &mut self,
        _asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<usize> {
        let cert_chain = self
            .cert_chain_mut(slot_id)
            .ok_or(CertStoreError::InvalidSlotId)?;

        let (root_cert_chain_len, device_cert_chain_len, dpe_leaf_cert_len) =
            cert_chain.refresh_ecc_cert_chain().await?;

        Ok(root_cert_chain_len + device_cert_chain_len + dpe_leaf_cert_len)
    }

    async fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        let cert_chain = self
            .cert_chain_mut(slot_id)
            .ok_or(CertStoreError::InvalidSlotId)?;

        let root_cert_chain_len = cert_chain.root_cert_chain_len;
        let (device_cert_chain_len, dpe_leaf_cert_len) = match (
            cert_chain.device_cert_chain_len,
            cert_chain.leaf_cert.as_ref(),
        ) {
            (Some(device_cert_len), Some(leaf_cert)) => (device_cert_len, leaf_cert.size),
            _ => {
                let (_, device_cert_len, leaf_cert_len) =
                    cert_chain.refresh_ecc_cert_chain().await?;
                (device_cert_len, leaf_cert_len)
            }
        };

        let total_cert_chain_len = root_cert_chain_len + device_cert_chain_len + dpe_leaf_cert_len;

        if offset >= total_cert_chain_len {
            return Err(CertStoreError::InvalidOffset);
        }

        let mut to_read = cert_portion.len().min(total_cert_chain_len - offset);
        let mut cert_chain_offset = offset;
        let mut pos = 0;

        while to_read > 0 {
            if cert_chain_offset < root_cert_chain_len {
                let cert_offset = cert_chain_offset;
                let len = cert_chain
                    .read_root_cert_chain(cert_offset, &mut cert_portion[pos..pos + to_read])?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            } else if cert_chain_offset < root_cert_chain_len + device_cert_chain_len {
                let cert_offset = cert_chain_offset - root_cert_chain_len;
                let len = cert_chain
                    .read_device_ecc_cert_chain(cert_offset, &mut cert_portion[pos..pos + to_read])
                    .await?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            } else {
                let cert_offset = cert_chain_offset - root_cert_chain_len - device_cert_chain_len;
                let len = cert_chain
                    .read_dpe_leaf_cert(cert_offset, &mut cert_portion[pos..pos + to_read])?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            }
        }

        Ok(pos)
    }

    async fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self
            .cert_chain_mut(slot_id)
            .ok_or(CertStoreError::InvalidSlotId)?;

        let root_cert_hash = cert_chain.root_cert_hash;
        cert_hash.copy_from_slice(&root_cert_hash[..SHA384_HASH_SIZE]);
        Ok(())
    }

    async fn sign_hash<'a>(
        &self,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self
            .cert_chain(slot_id)
            .ok_or(CertStoreError::InvalidSlotId)?;
        cert_chain.sign_with_leaf_key(hash, signature).await
    }

    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        None
    }

    fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
        None
    }
    fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}

async fn populate_idev_ecc384_cert(slot_id: u8) -> DevCertStoreResult<()> {
    if let Some(idev_cert) = IDEV_CERTS[slot_id as usize] {
        let mut cert_ctx = CertContext::new();

        while let Err(e) = cert_ctx.populate_idev_ecc384_cert(idev_cert).await {
            match e {
                CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
                _ => Err(DevCertStoreError::CaliptraApi(e))?,
            }
        }

        Ok(())
    } else {
        Err(DevCertStoreError::InvalidSlotId)
    }
}
