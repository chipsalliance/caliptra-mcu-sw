// Licensed under the Apache-2.0 license

//! Transport-neutral certificate provisioning policy and endorsement validation.
//! Requester authorization is separate from these content and identity checks.

#![no_std]
#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

pub mod certificate;

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
    pub const INVALID_RECORD: McuErrorCode = McuErrorCode::new(domain::CERT_STORE, 0, 5);
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

    pub fn validate_anchor(self) -> McuResult<()> {
        match self {
            Self::LDevId => Ok(()),
            Self::FmcAlias | Self::RtAlias => Err(errors::UNSUPPORTED_KEY),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateProvisioningPolicy {
    pub owner_key: Option<DeviceKey>,
    pub tenant_key: Option<DeviceKey>,
}

impl CertificateProvisioningPolicy {
    pub const DEFAULT: Self = Self {
        owner_key: Some(DeviceKey::LDevId),
        tenant_key: None,
    };

    pub const fn configured_key(self, role: EndorsementRole) -> Option<DeviceKey> {
        match role {
            EndorsementRole::Vendor => None,
            EndorsementRole::Owner => self.owner_key,
            EndorsementRole::Tenant => self.tenant_key,
        }
    }

    pub fn validate(self) -> McuResult<()> {
        for key in [self.owner_key, self.tenant_key].into_iter().flatten() {
            key.validate_anchor()?;
        }
        Ok(())
    }

    pub fn key_for_role(self, role: EndorsementRole) -> McuResult<DeviceKey> {
        let key = self
            .configured_key(role)
            .ok_or(errors::PROVISIONING_DISABLED)?;
        key.validate_anchor()?;
        Ok(key)
    }

    /// Accept only canonical IDs. Protocol-specific implicit selection is
    /// resolved by the adapter before entering this policy.
    pub fn validate_key(self, role: EndorsementRole, key_pair_id: u8) -> McuResult<DeviceKey> {
        let key = self.key_for_role(role)?;
        if key_pair_id != key.key_pair_id() {
            return Err(errors::KEY_MISMATCH);
        }
        Ok(key)
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
    fn default_policy_binds_owner_and_disables_other_roles() {
        let policy = CertificateProvisioningPolicy::default();
        assert_eq!(
            policy.key_for_role(EndorsementRole::Owner),
            Ok(DeviceKey::LDevId)
        );
        for role in [EndorsementRole::Vendor, EndorsementRole::Tenant] {
            assert_eq!(
                policy.key_for_role(role),
                Err(errors::PROVISIONING_DISABLED)
            );
        }
    }

    #[test]
    fn owner_binding_does_not_depend_on_an_existing_certificate() {
        let policy = CertificateProvisioningPolicy::default();
        assert_eq!(
            policy.validate_key(EndorsementRole::Owner, 1),
            Ok(DeviceKey::LDevId)
        );
        for id in [0, 2, 3, u8::MAX] {
            assert_eq!(
                policy.validate_key(EndorsementRole::Owner, id),
                Err(errors::KEY_MISMATCH)
            );
        }
    }

    #[test]
    fn tenant_requires_an_explicit_supported_binding() {
        let policy = CertificateProvisioningPolicy {
            tenant_key: Some(DeviceKey::LDevId),
            ..CertificateProvisioningPolicy::DEFAULT
        };
        assert_eq!(
            policy.validate_key(EndorsementRole::Tenant, 1),
            Ok(DeviceKey::LDevId)
        );
        assert_eq!(
            policy.validate_key(EndorsementRole::Tenant, 2),
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
                owner_key: Some(key),
                tenant_key: None,
            };
            assert_eq!(policy.validate(), Err(errors::UNSUPPORTED_KEY));
            assert_eq!(
                policy.validate_key(EndorsementRole::Owner, key.key_pair_id()),
                Err(errors::UNSUPPORTED_KEY)
            );
        }
    }
}
