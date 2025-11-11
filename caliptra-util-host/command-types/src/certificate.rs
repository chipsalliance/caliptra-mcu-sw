// Licensed under the Apache-2.0 license

//! Certificate Management Commands
//!
//! Command structures for certificate operations

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Placeholder certificate commands - implement as needed
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetIdevidCertRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetIdevidCertResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for GetIdevidCertRequest {
    type Response = GetIdevidCertResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetIdevidCert;
}

impl CommandResponse for GetIdevidCertResponse {}

/// Generic Get Certificate Request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertificateRequest {
    /// Certificate index to retrieve
    pub index: u32,
}

/// Generic Get Certificate Response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetCertificateResponse {
    pub common: CommonResponse,
    /// Size of the certificate data
    pub data_size: u32,
    /// Certificate data
    pub cert_data: [u8; 1024],
}

impl CommandRequest for GetCertificateRequest {
    type Response = GetCertificateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetCertificate;
}

impl CommandResponse for GetCertificateResponse {}

/// Generic Set Certificate Request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertificateRequest {
    /// Certificate index to set
    pub index: u32,
    /// Size of the certificate data
    pub data_size: u32,
    /// Certificate data
    pub cert_data: [u8; 1024],
}

/// Generic Set Certificate Response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetCertificateResponse {
    pub common: CommonResponse,
}

impl CommandRequest for SetCertificateRequest {
    type Response = SetCertificateResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::SetCertificate;
}

impl CommandResponse for SetCertificateResponse {}
