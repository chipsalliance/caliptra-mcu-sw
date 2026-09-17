// Licensed under the Apache-2.0 license

use der::asn1::{
    AnyRef, BitStringRef, GeneralizedTime, ObjectIdentifier, OctetStringRef, UintRef, UtcTime,
};
use der::{Decode, Encode, Header, Reader, Sequence, SliceReader, Tag, Tagged};
use mcu_caliptra_api::{get_ldevid_cert, DpeProfile, ScratchAlloc, LDEVID_CERT_RSP_BUF_SIZE};
use mcu_error::McuResult;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use crate::errors::{INVALID_ENDORSEMENT, KEY_MISMATCH};
use crate::DeviceKey;

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const MLDSA87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

pub const MAX_DEVICE_PUBLIC_KEY_SIZE: usize = mcu_caliptra_api::mailbox::MLDSA87_PUB_KEY_BYTE_SIZE;

#[derive(Sequence)]
struct Validity<'a> {
    not_before: AnyRef<'a>,
    not_after: AnyRef<'a>,
}

#[derive(Sequence)]
struct TbsCertificate<'a> {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    version: Option<u8>,
    serial_number: UintRef<'a>,
    signature: AlgorithmIdentifierRef<'a>,
    issuer: AnyRef<'a>,
    validity: Validity<'a>,
    subject: AnyRef<'a>,
    subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitStringRef<'a>>,
    #[asn1(
        context_specific = "3",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    extensions: Option<AnyRef<'a>>,
}

#[derive(Sequence)]
struct Certificate<'a> {
    tbs_certificate: TbsCertificate<'a>,
    signature_algorithm: AlgorithmIdentifierRef<'a>,
    signature: BitStringRef<'a>,
}

#[derive(Sequence)]
struct Attribute<'a> {
    oid: ObjectIdentifier,
    value: AnyRef<'a>,
}

#[derive(Sequence)]
struct Extension<'a> {
    oid: ObjectIdentifier,
    critical: Option<bool>,
    value: OctetStringRef<'a>,
}

#[derive(Sequence)]
struct EccSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Return the complete certificate length from its DER header.
pub fn certificate_len(prefix: &[u8]) -> McuResult<usize> {
    let mut reader = SliceReader::new(prefix).map_err(|_| INVALID_ENDORSEMENT)?;
    let header = Header::decode(&mut reader).map_err(|_| INVALID_ENDORSEMENT)?;
    if header.tag != Tag::Sequence || header.length.is_zero() {
        return Err(INVALID_ENDORSEMENT);
    }
    let length = (header.encoded_len().map_err(|_| INVALID_ENDORSEMENT)? + header.length)
        .map_err(|_| INVALID_ENDORSEMENT)?;
    usize::try_from(length).map_err(|_| INVALID_ENDORSEMENT)
}

fn validate_name(name: AnyRef<'_>) -> der::Result<()> {
    name.sequence(|reader| {
        while !reader.is_finished() {
            let set: AnyRef<'_> = reader.decode()?;
            if set.tag() != Tag::Set || set.value().is_empty() {
                return Err(set.tag().value_error());
            }
            let mut attributes = SliceReader::new(set.value())?;
            while !attributes.is_finished() {
                let _: Attribute<'_> = attributes.decode()?;
            }
        }
        Ok(())
    })
}

fn validate_time(time: AnyRef<'_>) -> der::Result<()> {
    match time.tag() {
        Tag::UtcTime => time.decode_as::<UtcTime>().map(|_| ()),
        Tag::GeneralizedTime => time.decode_as::<GeneralizedTime>().map(|_| ()),
        tag => Err(tag.value_error()),
    }
}

/// Validate certificate framing and algorithm, returning its borrowed public key.
/// Certificate signatures, trust, and validity-time policy remain verifier checks.
pub fn certificate_public_key(cert: &[u8], profile: DpeProfile) -> McuResult<&[u8]> {
    let cert = Certificate::from_der(cert).map_err(|_| INVALID_ENDORSEMENT)?;
    let tbs = &cert.tbs_certificate;
    let version = tbs.version.unwrap_or(0);
    if version > 2
        || (version == 0 && (tbs.issuer_unique_id.is_some() || tbs.subject_unique_id.is_some()))
        || (version != 2 && tbs.extensions.is_some())
        || cert.signature_algorithm != tbs.signature
        || cert.signature_algorithm.parameters.is_some()
    {
        return Err(INVALID_ENDORSEMENT);
    }
    validate_name(tbs.issuer).map_err(|_| INVALID_ENDORSEMENT)?;
    validate_name(tbs.subject).map_err(|_| INVALID_ENDORSEMENT)?;
    validate_time(tbs.validity.not_before).map_err(|_| INVALID_ENDORSEMENT)?;
    validate_time(tbs.validity.not_after).map_err(|_| INVALID_ENDORSEMENT)?;
    if let Some(extensions) = tbs.extensions {
        extensions
            .sequence(|reader| {
                while !reader.is_finished() {
                    let extension: Extension<'_> = reader.decode()?;
                    if extension.critical == Some(false) {
                        return Err(Tag::Boolean.value_error());
                    }
                }
                Ok(())
            })
            .map_err(|_| INVALID_ENDORSEMENT)?;
    }

    let spki = &tbs.subject_public_key_info;
    let public_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(INVALID_ENDORSEMENT)?;
    let signature = cert.signature.as_bytes().ok_or(INVALID_ENDORSEMENT)?;
    match profile {
        DpeProfile::P384Sha384 => {
            let curve = spki
                .algorithm
                .parameters
                .ok_or(INVALID_ENDORSEMENT)?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| INVALID_ENDORSEMENT)?;
            if spki.algorithm.oid != EC_PUBLIC_KEY
                || curve != SECP384R1
                || cert.signature_algorithm.oid != ECDSA_SHA384
                || public_key.len() != 1 + 2 * mcu_caliptra_api::ECDSA_P384_COORD_SIZE
                || public_key.first() != Some(&4)
            {
                return Err(INVALID_ENDORSEMENT);
            }
            let signature = EccSignature::from_der(signature).map_err(|_| INVALID_ENDORSEMENT)?;
            if signature.r.as_bytes().len() > mcu_caliptra_api::ECDSA_P384_COORD_SIZE
                || signature.s.as_bytes().len() > mcu_caliptra_api::ECDSA_P384_COORD_SIZE
            {
                return Err(INVALID_ENDORSEMENT);
            }
        }
        DpeProfile::Mldsa87 => {
            if spki.algorithm.oid != MLDSA87
                || spki.algorithm.parameters.is_some()
                || cert.signature_algorithm.oid != MLDSA87
                || public_key.len() != MAX_DEVICE_PUBLIC_KEY_SIZE
                || signature.len() != mcu_caliptra_api::DPE_MLDSA87_SIGNATURE_SIZE
            {
                return Err(INVALID_ENDORSEMENT);
            }
        }
    }
    Ok(public_key)
}

/// Read either a received endorsement or its staged/persisted flash contents.
pub trait EndorsementReader {
    async fn read(&self, offset: usize, out: &mut [u8]) -> McuResult<usize>;
}

impl EndorsementReader for [u8] {
    async fn read(&self, offset: usize, out: &mut [u8]) -> McuResult<usize> {
        let source = self.get(offset..).ok_or(INVALID_ENDORSEMENT)?;
        let len = source.len().min(out.len());
        out[..len].copy_from_slice(&source[..len]);
        Ok(len)
    }
}

/// Validate every certificate and bind the terminal public key to Caliptra's
/// LDevID. Only one endorsement certificate is staged at a time, in task scratch.
pub async fn validate_endorsement<A: ScratchAlloc, R: EndorsementReader + ?Sized>(
    alloc: &A,
    reader: &R,
    data_len: usize,
    capacity: usize,
    profile: DpeProfile,
    key: DeviceKey,
) -> McuResult<()> {
    key.validate_anchor()?;
    if data_len == 0 || data_len > capacity {
        return Err(INVALID_ENDORSEMENT);
    }
    let expected = {
        let mut cert = alloc.alloc(LDEVID_CERT_RSP_BUF_SIZE)?;
        let len = get_ldevid_cert(profile, &mut cert).await?;
        let public_key =
            certificate_public_key(cert.get(..len).ok_or(INVALID_ENDORSEMENT)?, profile)?;
        let mut expected = alloc.alloc(public_key.len())?;
        expected.copy_from_slice(public_key);
        expected
    };
    validate_with_public_key(alloc, reader, data_len, profile, &expected).await
}

async fn validate_with_public_key<A: ScratchAlloc, R: EndorsementReader + ?Sized>(
    alloc: &A,
    reader: &R,
    data_len: usize,
    profile: DpeProfile,
    expected_public_key: &[u8],
) -> McuResult<()> {
    if data_len == 0 {
        return Err(INVALID_ENDORSEMENT);
    }
    let mut offset = 0;
    while offset < data_len {
        let mut header = [0u8; 6];
        let header_len = header.len().min(data_len - offset);
        if reader.read(offset, &mut header[..header_len]).await? != header_len {
            return Err(INVALID_ENDORSEMENT);
        }
        let len = certificate_len(&header[..header_len])?;
        if len > data_len - offset {
            return Err(INVALID_ENDORSEMENT);
        }
        let mut cert = alloc.alloc(len)?;
        if reader.read(offset, &mut cert).await? != len {
            return Err(INVALID_ENDORSEMENT);
        }
        let public_key = certificate_public_key(&cert, profile)?;
        offset += len;
        if offset == data_len && public_key != expected_public_key {
            return Err(KEY_MISMATCH);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::Cell;
    use futures::executor::block_on;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
    struct Allocator {
        largest: Cell<usize>,
    }

    impl ScratchAlloc for Allocator {
        type Buf<'a> = Vec<u8>;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            self.largest.set(self.largest.get().max(len));
            Ok(vec![0; len])
        }
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.extend_from_slice(&[0x81, body.len() as u8]);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn oid(value: ObjectIdentifier) -> Vec<u8> {
        tlv(0x06, value.as_bytes())
    }

    fn public_key(profile: DpeProfile, byte: u8) -> Vec<u8> {
        match profile {
            DpeProfile::P384Sha384 => {
                let mut key = vec![byte; 97];
                key[0] = 4;
                key
            }
            DpeProfile::Mldsa87 => vec![byte; MAX_DEVICE_PUBLIC_KEY_SIZE],
        }
    }

    fn certificate(profile: DpeProfile, public_key: &[u8]) -> Vec<u8> {
        let (algorithm, signature_algorithm, signature) = match profile {
            DpeProfile::P384Sha384 => (
                sequence(&[&oid(EC_PUBLIC_KEY), &oid(SECP384R1)]),
                sequence(&[&oid(ECDSA_SHA384)]),
                sequence(&[&tlv(0x02, &[1]), &tlv(0x02, &[2])]),
            ),
            DpeProfile::Mldsa87 => (
                sequence(&[&oid(MLDSA87)]),
                sequence(&[&oid(MLDSA87)]),
                vec![1; 4627],
            ),
        };
        let spki = sequence(&[&algorithm, &tlv(0x03, &[&[0], public_key].concat())]);
        let validity = sequence(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"350101000000Z")]);
        let tbs = sequence(&[
            &tlv(0xa0, &tlv(0x02, &[2])),
            &tlv(0x02, &[1]),
            &signature_algorithm,
            &sequence(&[]),
            &validity,
            &sequence(&[]),
            &spki,
        ]);
        sequence(&[
            &tbs,
            &signature_algorithm,
            &tlv(0x03, &[&[0], signature.as_slice()].concat()),
        ])
    }

    #[test]
    fn parses_both_algorithms_without_allocating() {
        for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
            let key = public_key(profile, 1);
            let cert = certificate(profile, &key);
            assert_eq!(certificate_len(&cert[..6]), Ok(cert.len()));
            assert_eq!(certificate_public_key(&cert, profile), Ok(key.as_slice()));
        }
    }

    #[test]
    fn validates_complete_chains_one_certificate_at_a_time() {
        for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
            let key = public_key(profile, 1);
            let root = certificate(profile, &public_key(profile, 2));
            let leaf = certificate(profile, &key);
            let chain = [root.as_slice(), leaf.as_slice()].concat();
            let alloc = Allocator::default();
            assert_eq!(
                block_on(validate_with_public_key(
                    &alloc,
                    chain.as_slice(),
                    chain.len(),
                    profile,
                    &key
                )),
                Ok(()),
            );
            assert_eq!(alloc.largest.get(), root.len().max(leaf.len()));
            assert!(alloc.largest.get() < chain.len());
        }
    }

    #[test]
    fn terminal_public_key_must_match_the_device() {
        for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
            let expected = public_key(profile, 1);
            let wrong = certificate(profile, &public_key(profile, 2));
            assert_eq!(
                block_on(validate_with_public_key(
                    &Allocator::default(),
                    wrong.as_slice(),
                    wrong.len(),
                    profile,
                    &expected,
                )),
                Err(KEY_MISMATCH),
            );
        }
    }

    #[test]
    fn rejects_wrong_algorithm_and_public_key_shape() {
        for (profile, other) in [
            (DpeProfile::P384Sha384, DpeProfile::Mldsa87),
            (DpeProfile::Mldsa87, DpeProfile::P384Sha384),
        ] {
            let key = public_key(profile, 1);
            let cert = certificate(profile, &key);
            assert_eq!(
                certificate_public_key(&cert, other),
                Err(INVALID_ENDORSEMENT)
            );
            let short = certificate(profile, &key[..key.len() - 1]);
            assert_eq!(
                certificate_public_key(&short, profile),
                Err(INVALID_ENDORSEMENT)
            );
        }
        let mut compressed = public_key(DpeProfile::P384Sha384, 1);
        compressed[0] = 2;
        let cert = certificate(DpeProfile::P384Sha384, &compressed);
        assert_eq!(
            certificate_public_key(&cert, DpeProfile::P384Sha384),
            Err(INVALID_ENDORSEMENT)
        );
    }

    #[test]
    fn rejects_truncation_trailing_data_and_noncertificates() {
        for profile in [DpeProfile::P384Sha384, DpeProfile::Mldsa87] {
            let key = public_key(profile, 1);
            let cert = certificate(profile, &key);
            let mut trailing = cert.clone();
            trailing.push(0);
            for invalid in [
                vec![],
                vec![0x30, 1, 0],
                cert[..cert.len() - 1].to_vec(),
                trailing,
            ] {
                assert!(block_on(validate_with_public_key(
                    &Allocator::default(),
                    invalid.as_slice(),
                    invalid.len(),
                    profile,
                    &key,
                ))
                .is_err());
            }
        }
    }

    #[test]
    fn rejects_noncanonical_or_indefinite_der_lengths() {
        for header in [
            &[0x30, 0x80, 0, 0][..],
            &[0x30, 0x81, 1, 0][..],
            &[0x30, 0x82, 0, 128, 0, 0][..],
            &[0x30, 0][..],
            &[0x31, 1, 0][..],
        ] {
            assert_eq!(certificate_len(header), Err(INVALID_ENDORSEMENT));
        }
    }

    #[test]
    fn size_and_anchor_checks_precede_caliptra_access() {
        let alloc = Allocator::default();
        let data = [1u8; 8];
        for (len, capacity, key) in [
            (0, 8, DeviceKey::LDevId),
            (8, 7, DeviceKey::LDevId),
            (8, 8, DeviceKey::FmcAlias),
            (8, 8, DeviceKey::RtAlias),
        ] {
            assert!(block_on(validate_endorsement(
                &alloc,
                data.as_slice(),
                len,
                capacity,
                DpeProfile::P384Sha384,
                key,
            ))
            .is_err());
        }
        assert_eq!(alloc.largest.get(), 0);
    }

    #[test]
    fn validation_uses_the_authoritative_caliptra_certificate_for_each_algorithm() {
        use caliptra_api::mailbox::CommandId;
        use caliptra_mcu_libsyscall_caliptra::mailbox::MAILBOX_DRIVER_NUM;
        use caliptra_mcu_libtock_platform::Syscalls;
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc};

        let kernel = fake::Kernel::new();
        let mailbox = Rc::new(fake::FakeMailboxDriver::new());
        kernel.add_driver(&mailbox);
        for (profile, command) in [
            (DpeProfile::P384Sha384, CommandId::GET_LDEV_ECC384_CERT),
            (DpeProfile::Mldsa87, CommandId::GET_LDEV_MLDSA87_CERT),
        ] {
            let trusted = certificate(profile, &public_key(profile, 1));
            let mut response = vec![0; 12];
            response[8..12].copy_from_slice(&(trusted.len() as u32).to_le_bytes());
            response.extend_from_slice(&trusted);
            let checksum = caliptra_api::calc_checksum(0, &response[4..]);
            response[..4].copy_from_slice(&checksum.to_le_bytes());

            for (key_byte, expected) in [(1, Ok(())), (2, Err(KEY_MISMATCH))] {
                mailbox.add_ready_response(command.0, &response);
                let endorsement = certificate(profile, &public_key(profile, key_byte));
                let result = fake::wait_for_future_ready(Box::pin(validate_endorsement(
                    &Allocator::default(),
                    endorsement.as_slice(),
                    endorsement.len(),
                    endorsement.len(),
                    profile,
                    DeviceKey::LDevId,
                )));
                fake::Syscalls::unallow_ro(MAILBOX_DRIVER_NUM, 0);
                fake::Syscalls::unallow_rw(MAILBOX_DRIVER_NUM, 0);
                assert_eq!(result, expected);
                assert_eq!(mailbox.get_last_command(), Some(command.0));
                assert_eq!(
                    mailbox.get_last_ro_input().unwrap(),
                    caliptra_api::calc_checksum(command.0, &[]).to_le_bytes(),
                );
            }
        }
    }
}
