// Licensed under the Apache-2.0 license

use crate::checksum;
use core::mem;
use libsyscall_caliptra::mailbox::Mailbox;
use libtock_platform::{ErrorCode, Syscalls};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes};

/// API for interacting with the mailbox.
pub struct MailboxAPI<S: Syscalls> {
    syscall: Mailbox<S>,
}

impl<S: Syscalls> Default for MailboxAPI<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> MailboxAPI<S> {
    /// Creates a new instance of the Mailbox API.
    #[inline]
    pub fn new() -> Self {
        Self {
            syscall: Mailbox::new(),
        }
    }

    /// Executes a mailbox request and retrieves its response.
    pub async fn execute_command(
        &self,
        request: &MailboxRequest,
    ) -> Result<MailboxResponse, ErrorCode> {
        let mut buffer = [0u8; mem::size_of::<MailboxResponse>()];

        let response_size = self
            .syscall
            .execute(request.command_id(), request.as_bytes(), &mut buffer)
            .await?;
        let mut response = request.parse_response(&buffer[..response_size])?;
        response.verify()?;
        Ok(response)
    }
}

/// Trait for mailbox requests.
pub trait MailboxRequestTrait: FromBytes + IntoBytes + Immutable {
    /// Returns the command ID associated with the request.
    const COMMAND_ID: u32;
    type Response: MailboxResponseTrait;

    /// Populates the checksum field for the request.
    fn populate_checksum(&mut self) {
        let checksum =
            checksum::calc_checksum(Self::COMMAND_ID, &self.as_bytes()[mem::size_of::<i32>()..]);

        let mut hdr: Ref<&mut [u8], MailboxReqHeader> =
            Ref::<&mut [u8], MailboxReqHeader>::from_bytes(
                &mut self.as_mut_bytes()[..mem::size_of::<MailboxReqHeader>()],
            )
            .expect("Failed to create MailboxReqHeader");
        hdr.chksum = checksum;
    }

    /// Verifies the checksum of the response.
    fn verify_checksum(&mut self) -> Result<(), ErrorCode> {
        let calc_checksum = checksum::calc_checksum(
            Self::COMMAND_ID,
            &self.as_bytes()[mem::size_of::<MailboxRespHeader>()..],
        );
        let hdr: Ref<&mut [u8], MailboxReqHeader> = Ref::<&mut [u8], MailboxReqHeader>::from_bytes(
            &mut self.as_mut_bytes()[..mem::size_of::<MailboxReqHeader>()],
        )
        .expect("Failed to create MailboxReqHeader");

        if hdr.chksum == calc_checksum {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }
}

/// Header for mailbox requests.
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, PartialEq, Eq, KnownLayout, Immutable)]
pub struct MailboxReqHeader {
    pub chksum: u32,
}

/// Header for mailbox responses.
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, PartialEq, Eq, KnownLayout, Immutable)]
pub struct MailboxRespHeader {
    pub chksum: u32,
    pub fips_status: u32,
}

/// Enum defining all possible Mailbox Requests.
#[derive(Debug)]
pub enum MailboxRequest {
    GetImageLoadAddress(GetImageLoadAddressRequest),
    GetImageLocationOffset(GetImageLocationOffsetRequest),
    GetImageSize(GetImageSizeRequest),
    AuthorizeAndStash(AuthorizeAndStashRequest),
}

impl MailboxRequest {
    /// Retrieves the command ID for the request.
    #[inline]
    fn command_id(&self) -> u32 {
        match self {
            MailboxRequest::GetImageLoadAddress(_) => GetImageLoadAddressRequest::COMMAND_ID,
            MailboxRequest::GetImageLocationOffset(_) => GetImageLocationOffsetRequest::COMMAND_ID,
            MailboxRequest::GetImageSize(_) => GetImageSizeRequest::COMMAND_ID,
            MailboxRequest::AuthorizeAndStash(_) => AuthorizeAndStashRequest::COMMAND_ID,
        }
    }

    /// Converts the request into a byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        match self {
            MailboxRequest::GetImageLoadAddress(req) => req.as_bytes(),
            MailboxRequest::GetImageLocationOffset(req) => req.as_bytes(),
            MailboxRequest::GetImageSize(req) => req.as_bytes(),
            MailboxRequest::AuthorizeAndStash(req) => req.as_bytes(),
        }
    }

    /// Parses the response for the given request.
    fn parse_response(&self, response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        match self {
            MailboxRequest::GetImageLoadAddress(_) => {
                <GetImageLoadAddressRequest as MailboxRequestTrait>::Response::parse_response(
                    response,
                )
            }
            MailboxRequest::GetImageLocationOffset(_) => {
                <GetImageLocationOffsetRequest as MailboxRequestTrait>::Response::parse_response(
                    response,
                )
            }
            MailboxRequest::GetImageSize(_) => {
                <GetImageSizeRequest as MailboxRequestTrait>::Response::parse_response(response)
            }
            MailboxRequest::AuthorizeAndStash(_) => {
                <AuthorizeAndStashRequest as MailboxRequestTrait>::Response::parse_response(
                    response,
                )
            }
        }
    }
}

/// Enum defining all possible Mailbox Responses.
#[derive(Debug)]
pub enum MailboxResponse {
    GetImageLoadAddress(GetImageLoadAddressResponse),
    GetImageLocationOffset(GetImageLocationOffsetResponse),
    GetImageSize(GetImageSizeResponse),
    AuthorizeAndStash(AuthorizeAndStashResponse),
}

impl MailboxResponse {
    /// Verifies the integrity of the response.
    fn verify(&mut self) -> Result<(), ErrorCode> {
        match self {
            MailboxResponse::GetImageLoadAddress(resp) => resp.verify(),
            MailboxResponse::GetImageLocationOffset(resp) => resp.verify(),
            MailboxResponse::GetImageSize(resp) => resp.verify(),
            MailboxResponse::AuthorizeAndStash(resp) => resp.verify(),
        }
    }
}

/// Trait for mailbox responses.
pub trait MailboxResponseTrait: FromBytes + IntoBytes + Immutable {
    /// Populates the checksum field for the response.
    fn populate_checksum(&mut self) {
        let checksum = checksum::calc_checksum(0, &self.as_bytes()[mem::size_of::<i32>()..]);

        let mut hdr: Ref<&mut [u8], MailboxRespHeader> =
            Ref::<&mut [u8], MailboxRespHeader>::from_bytes(
                &mut self.as_mut_bytes()[..mem::size_of::<MailboxRespHeader>()],
            )
            .expect("Failed to create MailboxRespHeader");
        hdr.chksum = checksum;
    }

    /// Verifies the checksum of the response.
    fn verify_checksum(&mut self) -> Result<(), ErrorCode> {
        let calc_checksum =
            checksum::calc_checksum(0, &self.as_bytes()[mem::size_of::<MailboxRespHeader>()..]);
        let hdr: Ref<&mut [u8], MailboxRespHeader> =
            Ref::<&mut [u8], MailboxRespHeader>::from_bytes(
                &mut self.as_mut_bytes()[..mem::size_of::<MailboxRespHeader>()],
            )
            .expect("Failed to create MailboxRespHeader");

        if hdr.chksum == calc_checksum {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Verifies the FIPS status in the response header.
    fn verify_fips_status(&mut self) -> Result<(), ErrorCode> {
        let hdr: Ref<&mut [u8], MailboxRespHeader> =
            Ref::<&mut [u8], MailboxRespHeader>::from_bytes(
                &mut self.as_mut_bytes()[..mem::size_of::<MailboxRespHeader>()],
            )
            .expect("Failed to create MailboxRespHeader");

        if hdr.fips_status == 0 {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Performs all necessary verifications.
    fn verify(&mut self) -> Result<(), ErrorCode> {
        self.verify_checksum()?;
        self.verify_fips_status()
    }

    /// Parses the response for the given request type.
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode>;
}

/// Request to get the image load address.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageLoadAddressRequest {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageLoadAddressRequest {
    const COMMAND_ID: u32 = 0x494D_4C41; // "IMLA"
    type Response = GetImageLoadAddressResponse;
}

/// Response for the get image load address request.
#[repr(C)]
#[derive(Default, FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageLoadAddressResponse {
    pub hdr: MailboxRespHeader,
    pub load_address_high: u32,
    pub load_address_low: u32,
}

impl MailboxResponseTrait for GetImageLoadAddressResponse {
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        Self::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageLoadAddress)
            .map_err(|_| ErrorCode::Invalid)
    }
}

/// Request to get the image location offset.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageLocationOffsetRequest {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageLocationOffsetRequest {
    const COMMAND_ID: u32 = 0x494D_4C4F; // "IMLO"
    type Response = GetImageLocationOffsetResponse;
}

/// Response for the get image location offset request.
#[repr(C)]
#[derive(Default, FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageLocationOffsetResponse {
    pub hdr: MailboxRespHeader,
    pub offset: u32,
}

impl MailboxResponseTrait for GetImageLocationOffsetResponse {
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageLocationOffsetResponse::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageLocationOffset)
            .map_err(|_| ErrorCode::Invalid)
    }
}

/// Request to get the image size.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageSizeRequest {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageSizeRequest {
    const COMMAND_ID: u32 = 0x494D_535A; // "IMSZ"
    type Response = GetImageSizeResponse;
}

/// Response for the get image size request.
#[repr(C)]
#[derive(Default, FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageSizeResponse {
    pub hdr: MailboxRespHeader,
    pub size: u32,
}

impl MailboxResponseTrait for GetImageSizeResponse {
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageSizeResponse::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageSize)
            .map_err(|_| ErrorCode::Invalid)
    }
}

/// Request to authorize and stash an image.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct AuthorizeAndStashRequest {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
    pub measurement: [u8; 48],
    pub context: [u8; 48],
    pub flags: u32,
    pub source: u32,
}

// Create a default implementation for AuthorizeAndStashRequest
impl Default for AuthorizeAndStashRequest {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            fw_id: [0; 4],
            measurement: [0; 48],
            context: [0; 48],
            flags: 0,
            source: 0,
        }
    }
}

impl MailboxRequestTrait for AuthorizeAndStashRequest {
    const COMMAND_ID: u32 = 0x4154_5348; // "ATSH"
    type Response = AuthorizeAndStashResponse;
}

/// Response for the authorize and stash request.
#[repr(C)]
#[derive(Default, FromBytes, IntoBytes, Debug, Immutable)]
pub struct AuthorizeAndStashResponse {
    pub hdr: MailboxRespHeader,
    pub auth_req_result: u32,
}

/// Image is authorized.
pub const AUTHORIZED_IMAGE: u32 = 0xDEADC0DE;
/// Image is not authorized.
pub const IMAGE_NOT_AUTHORIZED: u32 = 0x21523F21;
/// Image hash mismatch.
pub const IMAGE_HASH_MISMATCH: u32 = 0x8BFB95CB;

impl MailboxResponseTrait for AuthorizeAndStashResponse {
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        AuthorizeAndStashResponse::try_read_from_bytes(response)
            .map(MailboxResponse::AuthorizeAndStash)
            .map_err(|_| ErrorCode::Invalid)
    }
}
