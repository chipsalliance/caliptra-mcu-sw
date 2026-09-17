// Licensed under the Apache-2.0 license

//! Transport-neutral certificate provisioning policy.
//! Requester authorization and endorsement-content validation are separate.

#![no_std]
#![forbid(unsafe_code)]

use caliptra_mcu_common_commands::{
    DEVICE_KEY_ID_FMC_ALIAS, DEVICE_KEY_ID_LDEV_ID, DEVICE_KEY_ID_RT_ALIAS,
};
use mcu_error::McuResult;

pub mod errors {
    use mcu_error::{domain, McuErrorCode};

    pub const PROVISIONING_DISABLED: McuErrorCode = McuErrorCode::new(domain::CERT_STORE, 0, 1);
    pub const KEY_MISMATCH: McuErrorCode = McuErrorCode::new(domain::CERT_STORE, 0, 2);
    pub const UNSUPPORTED_KEY: McuErrorCode = McuErrorCode::new(domain::CERT_STORE, 0, 3);
    pub const INVALID_ENDORSEMENT: McuErrorCode = McuErrorCode::new(domain::CERT_STORE, 0, 4);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndorsementRole {
    Vendor,
    Owner,
    Tenant,
}

/// Logical Caliptra identity, independent of the certificate's algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceKey {
    LDevId = DEVICE_KEY_ID_LDEV_ID,
    FmcAlias = DEVICE_KEY_ID_FMC_ALIAS,
    RtAlias = DEVICE_KEY_ID_RT_ALIAS,
}

impl DeviceKey {
    pub const fn key_pair_id(self) -> u8 {
        self as u8
    }

    pub const fn from_key_pair_id(id: u8) -> Option<Self> {
        match id as u32 {
            DEVICE_KEY_ID_LDEV_ID => Some(Self::LDevId),
            DEVICE_KEY_ID_FMC_ALIAS => Some(Self::FmcAlias),
            DEVICE_KEY_ID_RT_ALIAS => Some(Self::RtAlias),
            _ => None,
        }
    }

    pub fn validate_anchor_point(self) -> McuResult<()> {
        match self {
            Self::LDevId => Ok(()),
            Self::FmcAlias | Self::RtAlias => Err(errors::UNSUPPORTED_KEY),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateProvisioningPolicy {
    pub owner_anchor_point: Option<DeviceKey>,
    pub tenant_anchor_point: Option<DeviceKey>,
}

impl CertificateProvisioningPolicy {
    pub const DEFAULT: Self = Self {
        owner_anchor_point: Some(DeviceKey::LDevId),
        tenant_anchor_point: None,
    };

    pub const fn anchor_point(self, role: EndorsementRole) -> Option<DeviceKey> {
        match role {
            EndorsementRole::Vendor => None,
            EndorsementRole::Owner => self.owner_anchor_point,
            EndorsementRole::Tenant => self.tenant_anchor_point,
        }
    }

    pub fn validate(self) -> McuResult<()> {
        for key in [self.owner_anchor_point, self.tenant_anchor_point]
            .into_iter()
            .flatten()
        {
            key.validate_anchor_point()?;
        }
        Ok(())
    }

    pub fn validate_role(self, role: EndorsementRole) -> McuResult<()> {
        if role == EndorsementRole::Vendor {
            return Err(errors::PROVISIONING_DISABLED);
        }
        if let Some(key) = self.anchor_point(role) {
            key.validate_anchor_point()?;
        }
        Ok(())
    }

    /// Resolve and validate `key_pair_id` against the role's configured key anchor point:
    /// - Configured anchor point: `key_pair_id == 0` resolves to it; nonzero must match it.
    /// - No configured anchor point: requires an explicit nonzero `key_pair_id` for a supported anchor point.
    pub fn validate_key(self, role: EndorsementRole, key_pair_id: u8) -> McuResult<DeviceKey> {
        if role == EndorsementRole::Vendor {
            return Err(errors::PROVISIONING_DISABLED);
        }
        match self.anchor_point(role) {
            Some(key) => {
                key.validate_anchor_point()?;
                if key_pair_id == 0 || key_pair_id == key.key_pair_id() {
                    Ok(key)
                } else {
                    Err(errors::KEY_MISMATCH)
                }
            }
            None => {
                let key = DeviceKey::from_key_pair_id(key_pair_id).ok_or(errors::KEY_MISMATCH)?;
                key.validate_anchor_point()?;
                Ok(key)
            }
        }
    }
}

impl Default for CertificateProvisioningPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_pins_owner_and_leaves_tenant_unrestricted() {
        let policy = CertificateProvisioningPolicy::default();
        assert_eq!(
            policy.anchor_point(EndorsementRole::Owner),
            Some(DeviceKey::LDevId)
        );
        assert_eq!(policy.anchor_point(EndorsementRole::Tenant), None);
        assert_eq!(policy.validate_role(EndorsementRole::Owner), Ok(()));
        assert_eq!(policy.validate_role(EndorsementRole::Tenant), Ok(()));
        assert_eq!(
            policy.validate_role(EndorsementRole::Vendor),
            Err(errors::PROVISIONING_DISABLED)
        );
    }

    #[test]
    fn some_policy_resolves_zero_and_enforces_pinned_key() {
        let policy = CertificateProvisioningPolicy::default();
        assert_eq!(
            policy.validate_key(EndorsementRole::Owner, 0),
            Ok(DeviceKey::LDevId)
        );
        assert_eq!(
            policy.validate_key(EndorsementRole::Owner, 1),
            Ok(DeviceKey::LDevId)
        );
        for id in [2, 3, u8::MAX] {
            assert_eq!(
                policy.validate_key(EndorsementRole::Owner, id),
                Err(errors::KEY_MISMATCH)
            );
        }
    }

    #[test]
    fn none_policy_requires_explicit_supported_key_and_rejects_zero() {
        let policy = CertificateProvisioningPolicy::default();
        assert_eq!(
            policy.validate_key(EndorsementRole::Tenant, 0),
            Err(errors::KEY_MISMATCH)
        );
        assert_eq!(
            policy.validate_key(EndorsementRole::Tenant, 1),
            Ok(DeviceKey::LDevId)
        );
        for id in [2, 3] {
            assert_eq!(
                policy.validate_key(EndorsementRole::Tenant, id),
                Err(errors::UNSUPPORTED_KEY)
            );
        }
        assert_eq!(
            policy.validate_key(EndorsementRole::Tenant, u8::MAX),
            Err(errors::KEY_MISMATCH)
        );
        assert_eq!(
            policy.validate_key(EndorsementRole::Vendor, 1),
            Err(errors::PROVISIONING_DISABLED)
        );
    }

    #[test]
    fn unsupported_anchors_are_rejected() {
        for key in [DeviceKey::FmcAlias, DeviceKey::RtAlias] {
            let policy = CertificateProvisioningPolicy {
                owner_anchor_point: Some(key),
                tenant_anchor_point: None,
            };
            assert_eq!(policy.validate(), Err(errors::UNSUPPORTED_KEY));
            assert_eq!(
                policy.validate_key(EndorsementRole::Owner, key.key_pair_id()),
                Err(errors::UNSUPPORTED_KEY)
            );
        }
    }
}
