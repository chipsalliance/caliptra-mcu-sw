// Licensed under the Apache-2.0 license

//! ML-DSA-87 message-representative construction for external-`mu` signing.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

use crate::dpe::{CERTIFY_KEY_MLDSA87_PUBKEY_SIZE, DPE_MLDSA87_MU_SIZE};
use crate::{
    shake256_finish, shake256_hash, shake256_init, shake256_update, ApiAlloc, SHAKE256_CONTEXT_SIZE,
};

/// Width of the ML-DSA public-key hash `tr`.
pub const MLDSA87_TR_SIZE: usize = 64;

/// Maximum context length allowed by FIPS 204.
pub const MLDSA87_CONTEXT_MAX_SIZE: usize = u8::MAX as usize;

const PURE_MLDSA_DOMAIN_SEPARATOR: u8 = 0;

/// Calculate `tr = SHAKE256(raw_public_key, 64)`.
///
/// `raw_public_key` is the 2,592-byte ML-DSA-87 key returned by DPE
/// `CertifyKey`, not its DER SubjectPublicKeyInfo encoding.
#[inline(never)]
pub async fn mldsa87_compute_tr<A: ApiAlloc>(
    alloc: &A,
    raw_public_key: &[u8; CERTIFY_KEY_MLDSA87_PUBKEY_SIZE],
    tr: &mut [u8; MLDSA87_TR_SIZE],
) -> McuResult<()> {
    shake256_hash(alloc, raw_public_key, tr).await
}

/// Calculate the external `mu` consumed by DPE ML-DSA-87 `Sign`.
///
/// For pure ML-DSA this computes:
/// `SHAKE256(tr || 0x00 || len(context) || context || message_parts..., 64)`.
#[inline(never)]
pub async fn mldsa87_compute_mu<A: ApiAlloc>(
    alloc: &A,
    tr: &[u8; MLDSA87_TR_SIZE],
    context: &[u8],
    message_parts: &[&[u8]],
    mu: &mut [u8; DPE_MLDSA87_MU_SIZE],
) -> McuResult<()> {
    let domain = mldsa87_domain(context.len())?;
    let state_buffer = alloc.alloc(SHAKE256_CONTEXT_SIZE)?;
    let mut state = shake256_init(alloc, state_buffer, tr).await?;
    shake256_update(alloc, &mut state, &domain).await?;
    shake256_update(alloc, &mut state, context).await?;
    for part in message_parts {
        shake256_update(alloc, &mut state, part).await?;
    }
    shake256_finish(alloc, &mut state, mu).await
}

fn mldsa87_domain(context_len: usize) -> McuResult<[u8; 2]> {
    if context_len > MLDSA87_CONTEXT_MAX_SIZE {
        return Err(INVARIANT);
    }
    Ok([PURE_MLDSA_DOMAIN_SEPARATOR, context_len as u8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_mldsa_domain_encodes_context_length() {
        assert_eq!(mldsa87_domain(0).unwrap(), [0, 0]);
        assert_eq!(mldsa87_domain(255).unwrap(), [0, 255]);
        assert!(mldsa87_domain(256).is_err());
    }
}
