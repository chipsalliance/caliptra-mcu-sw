// Licensed under the Apache-2.0 license

//! Certificate store for the spdm-lib PAL.
//!
//! Slot 0 composes an SPDM cert chain from three portions:
//! 1. static endorsement/root chain
//! 2. DPE device chain (IDevID → RT alias, from Caliptra Core)
//! 3. DPE leaf certificate (CertifyKey, fetched on demand)
//!
//! Managed `AliasCert` slots store the owner/tenant endorsement chain installed
//! by SET_CERTIFICATE and expose it followed by the Caliptra alias/DPE tail.
//! [`SlotEndorsement`] dispatches to `ReadOnlyEndorsement` (slot 0) or
//! `ManagedEndorsement` (slots 1-2) without dynamic dispatch.

pub mod endorsement;
pub mod store;

use super::measurements::MeasurementProvider;
use super::*;
use caliptra_mcu_spdm_traits::{SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};
use endorsement::slot_index;
use mcu_caliptra_api_lite::{
    dpe_certify_key, dpe_get_cert_chain_chunk, dpe_sign_ecc_p384, walk_dpe_chain, ApiAlloc,
    DpeChainSink, DPE_LABEL_LEN, DPE_MAX_LEAF_CERT_SIZE,
};
#[cfg(feature = "set-certificate")]
use mcu_caliptra_api_lite::{sha_finish, sha_init, sha_update, HashAlgo, SHA_CONTEXT_SIZE};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};

/// 48-byte label fed to DPE `CertifyKey` for slot 0. Keep this stable so
/// slot-0 leaf-cert key continuity matches what existing tooling expects.
pub const SLOT0_LEAF_LABEL: [u8; DPE_LABEL_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Default KeyUsageMask for all Caliptra slots.
const DEFAULT_KEY_USAGE_MASK: u16 = 0x0003;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const DPE_IDEVID_AND_LDEVID_CERT_COUNT: usize = 2;

// ---------------------------------------------------------------------------
// Sinks for `walk_dpe_chain`
// ---------------------------------------------------------------------------

/// Counts bytes, discards them. Used to probe DPE chain length.
struct CountSink;
impl DpeChainSink for CountSink {
    async fn on_chunk(&mut self, _: &[u8]) -> McuResult<()> {
        Ok(())
    }
}

/// Counts DPE-chain bytes while finding the byte offset immediately after the
/// first `target_certs` DER certificates. This lets managed Owner/Tenant slots
/// reuse the existing streamed DPE-chain API while omitting the Caliptra
/// IDevID/LDevID prefix that is replaced by the provisioned owner chain.
struct DpeSkipPrefixSink {
    target_certs: usize,
    skipped_certs: usize,
    skip_len: usize,
    total: usize,
    header: [u8; 16],
    header_len: usize,
}

impl DpeSkipPrefixSink {
    fn new(target_certs: usize) -> Self {
        Self {
            target_certs,
            skipped_certs: 0,
            skip_len: 0,
            total: 0,
            header: [0; 16],
            header_len: 0,
        }
    }
}

impl DpeChainSink for DpeSkipPrefixSink {
    async fn on_chunk(&mut self, chunk: &[u8]) -> McuResult<()> {
        let chunk_start = self.total;
        let mut pos = 0usize;
        while self.skipped_certs < self.target_certs && pos < chunk.len() {
            let global = chunk_start.checked_add(pos).ok_or(INVARIANT)?;
            if global < self.skip_len {
                let skip = (self.skip_len - global).min(chunk.len() - pos);
                pos = pos.checked_add(skip).ok_or(INVARIANT)?;
                continue;
            }
            if global != self.skip_len {
                return Err(INVARIANT);
            }

            let room = self.header.len().saturating_sub(self.header_len);
            if room == 0 {
                return Err(INVARIANT);
            }
            let take = room.min(chunk.len() - pos);
            self.header[self.header_len..self.header_len + take]
                .copy_from_slice(&chunk[pos..pos + take]);
            self.header_len += take;
            pos += take;

            if let Some(cert_len) = der_first_seq_len(&self.header[..self.header_len]) {
                if cert_len == 0 {
                    return Err(INVARIANT);
                }
                self.skip_len = self.skip_len.checked_add(cert_len).ok_or(INVARIANT)?;
                self.skipped_certs += 1;
                self.header_len = 0;
            } else if self.header_len == self.header.len() {
                return Err(INVARIANT);
            }
        }
        self.total = self.total.checked_add(chunk.len()).ok_or(INVARIANT)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

impl<M: MeasurementProvider> SpdmPalCertStore for McuSpdmPal<M> {
    fn supported_slots(&self) -> u8 {
        let mut mask = 0u8;
        for (i, slot) in self.cert_store.cert_slots().iter().enumerate() {
            if slot.is_supported() {
                mask |= 1 << endorsement::DEFAULT_SLOT_MAP[i];
            }
        }
        mask
    }

    fn provisioned_slots(&self) -> u8 {
        let mut mask = 0u8;
        for (i, slot) in self.cert_store.cert_slots().iter().enumerate() {
            if slot.is_provisioned() {
                mask |= 1 << endorsement::DEFAULT_SLOT_MAP[i];
            }
        }
        mask
    }

    async fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        let cert_slot = &self.cert_store.cert_slots()[idx];
        let capacity = cert_slot
            .endorsement
            .capacity(SpdmPalAsymAlgo::EccP384)
            .await
            .map_err(|_| INVARIANT)?;
        let dpe_skip = if cert_slot.stores_complete_chain() {
            DPE_IDEVID_AND_LDEVID_CERT_COUNT
        } else {
            0
        };
        let (dpe_len, dpe_skip_len) = dpe_chain_len_and_skip_prefix(self, dpe_skip).await?;
        let leaf_len = probe_leaf_len_for_slot(self, slot).await?;
        capacity
            .checked_add(dpe_len.checked_sub(dpe_skip_len).ok_or(INVARIANT)?)
            .and_then(|n| n.checked_add(leaf_len))
            .ok_or(INVARIANT)
    }

    #[inline]
    fn set_certificate_authorized(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _key_pair_id: u8,
        _cert_model: u8,
        _erase: bool,
    ) -> bool {
        #[cfg(feature = "set-certificate")]
        {
            slot_index(slot)
                .and_then(|idx| self.cert_store.cert_slots().get(idx))
                .map(|slot| slot.is_writable())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = slot;
            false
        }
    }

    async fn validate_set_certificate_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            let cert_slot = &self.cert_store.cert_slots()[idx];
            if !cert_slot.is_writable() || cert_chain.is_empty() {
                return Err(INVARIANT);
            }
            if cert_model != CERT_MODEL_ALIAS_CERT {
                return Err(INVARIANT);
            }
            if !matches!(key_pair_id, 1..=3) {
                return Err(INVARIANT);
            }
            if cert_chain.len()
                > cert_slot
                    .endorsement
                    .capacity(SpdmPalAsymAlgo::EccP384)
                    .await
                    .map_err(|_| INVARIANT)?
            {
                return Err(INVARIANT);
            }
            validate_der_cert_chain(cert_chain)?;
            validate_set_certificate_root_hash(self, root_hash, cert_chain).await?;
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, key_pair_id, cert_model, root_hash, cert_chain);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if let Some(n) = self.cert_store.get_cached_chain_len(slot) {
            return Ok(n as usize);
        }
        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .await
            .map_err(|_| INVARIANT)?;
        let total = if cert_slot.stores_complete_chain() {
            let (dpe_len, dpe_skip_len) =
                dpe_chain_len_and_skip_prefix(self, DPE_IDEVID_AND_LDEVID_CERT_COUNT).await?;
            let leaf_len = probe_leaf_len_for_slot(self, slot).await?;
            slot_chain_len
                .checked_add(dpe_len.checked_sub(dpe_skip_len).ok_or(INVARIANT)?)
                .and_then(|n| n.checked_add(leaf_len))
                .ok_or(INVARIANT)?
        } else {
            let dpe_len = walk_dpe_chain(self, &mut CountSink).await?;
            let leaf_len = probe_leaf_len_for_slot(self, slot).await?;
            (slot_chain_len as u32)
                .checked_add(dpe_len)
                .and_then(|n| n.checked_add(leaf_len as u32))
                .ok_or(INVARIANT)? as usize
        };
        self.cert_store.set_cached_chain_len(slot, total as u32);
        Ok(total)
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.cert_slots()[idx]
            .endorsement
            .root_cert_hash(SpdmPalAsymAlgo::EccP384, out)
            .await
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if dst.is_empty() {
            return Ok(0);
        }
        let total = self.cert_store.cached_chain_len_or_zero(slot);
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .await
            .map_err(|_| INVARIANT)?;
        let want = (total - offset).min(dst.len());
        // Read-only layout: [endorsement] [DPE chain] [leaf cert]
        // Managed AliasCert layout: [installed chain] [DPE chain without
        // Caliptra IDevID/LDevID] [leaf cert]. The latter matches OCP owner
        // provisioning, where SET_CERTIFICATE replaces the device-identity
        // prefix with Owner Root + Endorsed LDevID.
        let endorsement_len = slot_chain_len;
        let dpe_skip = if cert_slot.stores_complete_chain() {
            DPE_IDEVID_AND_LDEVID_CERT_COUNT
        } else {
            0
        };
        let (dpe_len, dpe_skip_len) = dpe_chain_len_and_skip_prefix(self, dpe_skip).await?;
        let dpe_tail_len = dpe_len.checked_sub(dpe_skip_len).ok_or(INVARIANT)?;
        let leaf_label = leaf_label_for_slot(slot);
        let leaf_len = probe_leaf_len_for_label(self, &leaf_label).await? as usize;
        if total != endorsement_len + dpe_tail_len + leaf_len {
            return Err(INVARIANT);
        }

        let mut written = 0usize;
        let mut cur_offset = offset;

        // 1. Endorsement region
        if cur_offset < endorsement_len && written < want {
            let n = cert_slot
                .endorsement
                .read(
                    SpdmPalAsymAlgo::EccP384,
                    cur_offset,
                    &mut dst[written..want],
                )
                .await
                .map_err(|_| INVARIANT)?;
            written += n;
            cur_offset = offset + written;
        }

        // 2. DPE-chain region
        let dpe_start = endorsement_len;
        let dpe_end = dpe_start + dpe_tail_len;
        if cur_offset < dpe_end && written < want {
            let dpe_off = dpe_skip_len + cur_offset - dpe_start;
            let dpe_take = (dpe_end - cur_offset).min(want - written);
            let got = dpe_get_cert_chain_chunk(
                self,
                dpe_off as u32,
                &mut dst[written..written + dpe_take],
            )
            .await?;
            if got != dpe_take {
                return Err(INTERNAL_BUG);
            }
            written += dpe_take;
            cur_offset += dpe_take;
        }

        // 3. Leaf-cert region
        if cur_offset >= dpe_end && written < want {
            let mut leaf = ApiAlloc::alloc(self, leaf_len)?;
            let got = dpe_certify_key(self, &leaf_label, &mut leaf[..]).await?;
            if got != leaf_len {
                return Err(INTERNAL_BUG);
            }
            let leaf_off = cur_offset - dpe_end;
            let leaf_take = want - written;
            dst[written..written + leaf_take]
                .copy_from_slice(&leaf[leaf_off..leaf_off + leaf_take]);
            written += leaf_take;
        }
        Ok(written)
    }

    async fn sign_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        digest: &[u8],
        signature: &mut [u8],
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if slot != 0 {
            let _key_pair_id = self.cert_store.cert_slots()[idx]
                .key_pair_id
                .ok_or(INVARIANT)?;
        }
        let leaf_label = leaf_label_for_slot(slot);
        dpe_sign_ecc_p384(self, &leaf_label, digest, signature).await
    }

    async fn write_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                endorsement::SlotEndorsement::Managed(e) => *e,
                endorsement::SlotEndorsement::ReadOnly(_) => {
                    return Err(mcu_error::codes::NOT_IMPLEMENTED);
                }
                endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
            };
            let managed = managed
                .write_updated(algo, key_pair_id, cert_info, root_hash, data)
                .await?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
            cert_slot.key_pair_id = Some(key_pair_id);
            cert_slot.cert_info = Some(cert_info);
            self.cert_store.invalidate_cache(slot);
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, key_pair_id, cert_info, root_hash, data);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn erase_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                endorsement::SlotEndorsement::Managed(e) => *e,
                endorsement::SlotEndorsement::ReadOnly(_) => {
                    return Err(mcu_error::codes::NOT_IMPLEMENTED);
                }
                endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
            };
            let managed = managed.erase_updated(algo).await?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
            cert_slot.clear_metadata();
            self.cert_store.invalidate_cache(slot);
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    fn key_pair_id(&self, slot: u8) -> Option<u8> {
        let idx = slot_index(slot)?;
        self.cert_store.cert_slots()[idx].key_pair_id
    }

    fn cert_info(&self, slot: u8) -> Option<u8> {
        let idx = slot_index(slot)?;
        if !self.cert_store.cert_slots()[idx].is_provisioned() {
            return None;
        }
        self.cert_store.cert_slots()[idx].cert_info
    }

    fn key_usage_mask(&self, slot: u8) -> Option<u16> {
        let idx = slot_index(slot)?;
        let cert_slot = &self.cert_store.cert_slots()[idx];
        if !cert_slot.is_provisioned() {
            return None;
        }
        #[cfg(feature = "set-certificate")]
        {
            match &cert_slot.endorsement {
                endorsement::SlotEndorsement::Managed(e) => e.key_usage_mask(),
                _ => Some(DEFAULT_KEY_USAGE_MASK),
            }
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            Some(DEFAULT_KEY_USAGE_MASK)
        }
    }

    #[inline]
    fn cached_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo) -> Option<[u8; 48]> {
        self.cert_store.cached_chain_digest(slot)
    }

    #[inline]
    fn cache_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo, digest: &[u8]) {
        self.cert_store.cache_chain_digest(slot, digest);
    }

    async fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> McuResult<()> {
        mcu_caliptra_api_lite::rng_generate(self, out).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Probe the DPE leaf-cert size by calling `CertifyKey` and
/// discarding the cert bytes. Deterministic, so subsequent calls
/// produce identical sizes.
async fn probe_leaf_len_for_slot<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    slot: u8,
) -> McuResult<usize> {
    let label = leaf_label_for_slot(slot);
    probe_leaf_len_for_label(pal, &label).await
}

async fn probe_leaf_len_for_label<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    label: &[u8; DPE_LABEL_LEN],
) -> McuResult<usize> {
    let mut buf = ApiAlloc::alloc(pal, DPE_MAX_LEAF_CERT_SIZE)?;
    let n = dpe_certify_key(pal, label, &mut buf[..]).await?;
    Ok(n)
}

async fn dpe_chain_len_and_skip_prefix<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    skip_certs: usize,
) -> McuResult<(usize, usize)> {
    if skip_certs == 0 {
        return Ok((walk_dpe_chain(pal, &mut CountSink).await? as usize, 0));
    }
    let mut sink = DpeSkipPrefixSink::new(skip_certs);
    let total = walk_dpe_chain(pal, &mut sink).await? as usize;
    if sink.skipped_certs != skip_certs || sink.skip_len > total {
        return Err(INVARIANT);
    }
    Ok((total, sink.skip_len))
}

fn leaf_label_for_slot(slot: u8) -> [u8; DPE_LABEL_LEN] {
    if slot == 0 {
        return SLOT0_LEAF_LABEL;
    }
    let mut label = SLOT0_LEAF_LABEL;
    label[0] = b'S';
    label[1] = b'P';
    label[2] = b'D';
    label[3] = b'M';
    label[4] = b'-';
    label[5] = b'S';
    label[6] = b'L';
    label[7] = b'O';
    label[8] = b'T';
    label[9] = b'-';
    label[10] = slot;
    label[47] = slot;
    label
}

#[cfg(feature = "set-certificate")]
async fn validate_set_certificate_root_hash<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    root_hash: &[u8; 48],
    cert_chain: &[u8],
) -> McuResult<()> {
    let root_len = der_first_seq_len(cert_chain).ok_or(INVARIANT)?;
    let root_cert = cert_chain.get(..root_len).ok_or(INVARIANT)?;
    let sha_buf = ApiAlloc::alloc(pal, SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(pal, sha_buf, HashAlgo::Sha384, &[]).await?;
    sha_update(pal, &mut state, root_cert).await?;
    let mut digest = [0u8; 48];
    sha_finish(pal, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(INVARIANT);
    }
    Ok(())
}

fn validate_der_cert_chain(mut der_chain: &[u8]) -> McuResult<()> {
    let mut cert_count = 0usize;
    while !der_chain.is_empty() {
        let cert_len = der_first_seq_len(der_chain).ok_or(INVARIANT)?;
        if cert_len == 0 || cert_len > der_chain.len() {
            return Err(INVARIANT);
        }
        validate_der_x509_certificate(&der_chain[..cert_len])?;
        der_chain = &der_chain[cert_len..];
        cert_count = cert_count.checked_add(1).ok_or(INVARIANT)?;
    }
    if cert_count == 0 {
        return Err(INVARIANT);
    }
    Ok(())
}

fn validate_der_x509_certificate(cert_der: &[u8]) -> McuResult<()> {
    let (tag, content, consumed) = der_tlv(cert_der).ok_or(INVARIANT)?;
    if tag != 0x30 || consumed != cert_der.len() {
        return Err(INVARIANT);
    }
    let mut rest = content;
    let (tag, _tbs, n) = der_tlv(rest).ok_or(INVARIANT)?;
    if tag != 0x30 {
        return Err(INVARIANT);
    }
    rest = rest.get(n..).ok_or(INVARIANT)?;
    let (tag, _sig_alg, n) = der_tlv(rest).ok_or(INVARIANT)?;
    if tag != 0x30 {
        return Err(INVARIANT);
    }
    rest = rest.get(n..).ok_or(INVARIANT)?;
    let (tag, sig_value, n) = der_tlv(rest).ok_or(INVARIANT)?;
    if tag != 0x03 || sig_value.is_empty() {
        return Err(INVARIANT);
    }
    rest = rest.get(n..).ok_or(INVARIANT)?;
    if !rest.is_empty() {
        return Err(INVARIANT);
    }
    Ok(())
}

fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.first()?;
    let (len, len_len) = der_len(&buf[1..])?;
    let content_start = 1usize.checked_add(len_len)?;
    let consumed = content_start.checked_add(len)?;
    let content = buf.get(content_start..consumed)?;
    Some((tag, content, consumed))
}

fn der_len(buf: &[u8]) -> Option<(usize, usize)> {
    let len_byte = *buf.first()?;
    if len_byte & 0x80 == 0 {
        return Some((len_byte as usize, 1));
    }
    let n = (len_byte & 0x7f) as usize;
    if n == 0 || n > 4 || buf.len() < 1 + n {
        return None;
    }
    let mut content = 0usize;
    for &b in &buf[1..1 + n] {
        content = content.checked_shl(8)?;
        content = content.checked_add(b as usize)?;
    }
    Some((content, 1 + n))
}

#[cfg(test)]
fn dpe_alias_tail_offset(der_chain: &[u8], tail_cert_count: usize) -> McuResult<usize> {
    let mut offsets = [0usize; 8];
    let mut cert_count = 0usize;
    let mut offset = 0usize;
    while offset < der_chain.len() {
        if cert_count >= offsets.len() {
            return Err(INVARIANT);
        }
        offsets[cert_count] = offset;
        let cert_len = der_first_seq_len(&der_chain[offset..]).ok_or(INVARIANT)?;
        offset = offset.checked_add(cert_len).ok_or(INVARIANT)?;
        cert_count += 1;
    }
    if offset != der_chain.len() || cert_count <= tail_cert_count {
        return Err(INVARIANT);
    }
    Ok(offsets[cert_count - tail_cert_count])
}

/// Parse `len(TLV)` for the leading X.509 `SEQUENCE` in `buf` and
/// return `tag_and_length_bytes + content_bytes` — i.e. the total
/// DER encoding size of the first certificate in the chain. Returns
/// `None` on malformed input.
#[allow(dead_code)]
fn der_first_seq_len(buf: &[u8]) -> Option<usize> {
    // Tag 0x30 = SEQUENCE.
    if buf.len() < 2 || buf[0] != 0x30 {
        return None;
    }
    let len_byte = buf[1];
    if len_byte & 0x80 == 0 {
        // Short form: length fits in 7 bits.
        Some(2 + len_byte as usize)
    } else {
        // Long form: low 7 bits = number of length bytes.
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut content = 0usize;
        for &b in &buf[2..2 + n] {
            content = content.checked_shl(8)?;
            content = content.checked_add(b as usize)?;
        }
        Some(2 + n + content)
    }
}

#[cfg(test)]
mod tests {
    use super::{der_first_seq_len, dpe_alias_tail_offset, validate_der_cert_chain};

    #[test]
    fn der_short_form() {
        // SEQUENCE { 0x05 } len-byte = 0x01 → total = 2 + 1 = 3
        assert_eq!(der_first_seq_len(&[0x30, 0x01, 0x05]), Some(3));
    }

    #[test]
    fn der_long_form_two_byte_len() {
        // SEQUENCE, length-of-length = 2, content_len = 0x0102 = 258
        // Total DER encoding = tag(1) + len-of-len(1) + len(2) + content(258) = 262
        let mut buf = [0u8; 262];
        buf[0] = 0x30;
        buf[1] = 0x82;
        buf[2] = 0x01;
        buf[3] = 0x02;
        assert_eq!(der_first_seq_len(&buf), Some(262));
    }

    #[test]
    fn der_malformed_returns_none() {
        assert_eq!(der_first_seq_len(&[]), None);
        assert_eq!(der_first_seq_len(&[0x31, 0x01]), None); // wrong tag
        assert_eq!(der_first_seq_len(&[0x30]), None); // truncated
    }

    #[test]
    fn validate_der_cert_chain_accepts_concatenated_sequences() {
        let cert = minimal_x509_cert_der();
        let chain = [&cert[..], &cert[..]].concat();

        validate_der_cert_chain(&chain).unwrap();
    }

    #[test]
    fn validate_der_cert_chain_rejects_empty_and_trailing_garbage() {
        assert!(validate_der_cert_chain(&[]).is_err());
        assert!(validate_der_cert_chain(&[0x30, 0x01, 0x11, 0xff]).is_err());
    }

    fn minimal_x509_cert_der() -> [u8; 9] {
        // Certificate ::= SEQUENCE {
        //   tbsCertificate      SEQUENCE {},
        //   signatureAlgorithm  SEQUENCE {},
        //   signatureValue      BIT STRING { unused-bits = 0 }
        // }
        [0x30, 0x07, 0x30, 0x00, 0x30, 0x00, 0x03, 0x01, 0x00]
    }

    #[test]
    fn dpe_alias_tail_offset_selects_last_two_certs() {
        let chain = [
            &[0x30, 0x01, 0x11][..],
            &[0x30, 0x01, 0x22][..],
            &[0x30, 0x01, 0x33][..],
            &[0x30, 0x01, 0x44][..],
        ]
        .concat();

        assert_eq!(dpe_alias_tail_offset(&chain, 2).unwrap(), 6);
        assert_eq!(&chain[6..], &[0x30, 0x01, 0x33, 0x30, 0x01, 0x44]);
    }

    #[test]
    fn dpe_alias_tail_offset_rejects_short_chain() {
        let chain = [&[0x30, 0x01, 0x11][..], &[0x30, 0x01, 0x22][..]].concat();
        assert!(dpe_alias_tail_offset(&chain, 2).is_err());
    }
}
