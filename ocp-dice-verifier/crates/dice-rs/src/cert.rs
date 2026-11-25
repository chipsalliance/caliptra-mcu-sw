// Licensed under the Apache-2.0 license

//! Helper utilities for extracting DICE extensions from X.509 certificates.

use crate::error::{DiceError, Result};
use crate::kp::DiceKeyPurpose;
use crate::multi_tcb_info::MultiTcbInfo;
use crate::oids::*;
use crate::tcb_info::TcbInfo;
use crate::ueid::Ueid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Standard X.509 Extended Key Usage OID: 2.5.29.37
const OID_EXTENDED_KEY_USAGE: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 37);

/// Extracted DICE extensions from an X.509 certificate.
#[derive(Default)]
pub struct DiceExtensions<'a> {
    /// Single TcbInfo extension, if present (`tcg-dice-TcbInfo`).
    pub tcb_info: Option<TcbInfo<'a>>,

    /// MultiTcbInfo extension, if present (`tcg-dice-MultiTcbInfo`).
    pub multi_tcb_info: Option<MultiTcbInfo<'a>>,

    /// Ueid extension, if present (`tcg-dice-Ueid`).
    pub ueid: Option<Ueid<'a>>,

    /// DICE Key Purposes present in Extended Key Usage.
    pub key_purposes: Vec<DiceKeyPurpose>,
}

impl<'a> DiceExtensions<'a> {
    /// Extracts all DICE extensions present in an `X509Certificate`.
    pub fn from_x509_cert(cert: &X509Certificate<'a>) -> Result<Self> {
        let mut dice = Self::default();

        for ext in cert.extensions() {
            let oid_str = ext.oid.to_id_string();
            let parsed_oid = asn1::ObjectIdentifier::from_string(&oid_str);

            if let Some(ref oid) = parsed_oid {
                if *oid == OID_TCG_DICE_TCB_INFO {
                    dice.tcb_info = Some(TcbInfo::from_der(ext.value)?);
                } else if *oid == OID_TCG_DICE_MULTI_TCB_INFO {
                    dice.multi_tcb_info = Some(MultiTcbInfo::from_der(ext.value)?);
                } else if *oid == OID_TCG_DICE_UEID {
                    dice.ueid = Some(Ueid::from_der(ext.value)?);
                } else if *oid == OID_EXTENDED_KEY_USAGE {
                    if let Ok(seq) =
                        asn1::parse_single::<asn1::SequenceOf<asn1::ObjectIdentifier>>(ext.value)
                    {
                        for eku_oid in seq {
                            if let Some(kp) = DiceKeyPurpose::from_oid(&eku_oid) {
                                dice.key_purposes.push(kp);
                            }
                        }
                    }
                }
            }
        }

        Ok(dice)
    }

    /// Parses an X.509 certificate in DER format and extracts its DICE extensions.
    pub fn from_der_cert(der: &'a [u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| DiceError::Certificate(format!("{:?}", e)))?;
        Self::from_x509_cert(&cert)
    }
}
