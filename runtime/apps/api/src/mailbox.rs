use libsyscall_caliptra::mailbox::Mailbox;
use libtock_platform::{ErrorCode, Syscalls};
use zerocopy::{FromBytes, Immutable, IntoBytes, TryFromBytes};

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
        let mut buffer = [0u8; 64];
        let response_size = self
            .syscall
            .execute(request.command_id(), request.as_bytes(), &mut buffer)
            .await?;
        let mut response = request.parse_response(&buffer[..response_size])?;
        response.verify()?;
        Ok(response)
    }
}

pub trait MailboxRequestTrait: FromBytes + IntoBytes {
    /// Returns the command ID associated with the request.
    fn command_id(&self) -> u32;

    /// Populates the checksum field for the request.
    fn populate_checksum(&mut self) {
        let mut sum: u32 = self
            .command_id()
            .to_le_bytes()
            .iter()
            .map(|&b| b as u32)
            .sum();
        let bytes = self.as_mut_bytes();
        sum = sum.wrapping_add(bytes[4..].iter().map(|&b| b as u32).sum::<u32>());
        bytes[0..4].copy_from_slice(&0u32.wrapping_sub(sum).to_le_bytes());
    }

    /// Parses the response for the given request type.
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode>;
}

/// Enum defining all possible Mailbox Requests
#[derive(Debug)]
pub enum MailboxRequest {
    GetImageLoadAddress(GetImageLoadAddressRequest),
    GetImageLocationOffset(GetImageLocationOffsetRequest),
    GetImageSize(GetImageSizeRequest),
    AuthorizeAndStash(AuthorizeAndStashRequest),
}

impl MailboxRequest {
    /// Retrieves the command ID for the request.
    fn command_id(&self) -> u32 {
        match self {
            MailboxRequest::GetImageLoadAddress(req) => req.command_id(),
            MailboxRequest::GetImageLocationOffset(req) => req.command_id(),
            MailboxRequest::GetImageSize(req) => req.command_id(),
            MailboxRequest::AuthorizeAndStash(req) => req.command_id(),
        }
    }

    /// Converts the request into a byte slice.
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
                GetImageLoadAddressRequest::parse_response(response)
            }
            MailboxRequest::GetImageLocationOffset(_) => {
                GetImageLocationOffsetRequest::parse_response(response)
            }
            MailboxRequest::GetImageSize(_) => GetImageSizeRequest::parse_response(response),
            MailboxRequest::AuthorizeAndStash(_) => {
                AuthorizeAndStashRequest::parse_response(response)
            }
        }
    }
}

/// Enum defining all possible Mailbox Responses
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

/// Trait for mailbox responses
pub trait MailboxResponseTrait: FromBytes + IntoBytes {
    /// Verifies the checksum of the response.
    fn verify_checksum(&mut self) -> Result<(), ErrorCode> {
        let sum: u32 = self.as_mut_bytes().iter().map(|&b| b as u32).sum();
        if sum == 0 {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Verifies the FIPS status in the response header.
    fn verify_fips_status(&mut self) -> Result<(), ErrorCode> {
        let header =
            ResponseHeader::read_from_bytes(self.as_mut_bytes()).map_err(|_| ErrorCode::Fail)?;
        if header.fips_status == 0 {
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
}

/// Response header structure
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct ResponseHeader {
    pub chksum: u32,
    pub fips_status: u32,
}

/// GetImageLoadAddress
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageLoadAddressRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageLoadAddressRequest {
    fn command_id(&self) -> u32 {
        0x494D_4C41 // "IMLA"
    }
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageLoadAddressResponse::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageLoadAddress)
            .map_err(|_| ErrorCode::Invalid)
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug)]
pub struct GetImageLoadAddressResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub load_address_high: u32,
    pub load_address_low: u32,
}

impl MailboxResponseTrait for GetImageLoadAddressResponse {}

/// GetImageLocationOffset
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageLocationOffsetRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageLocationOffsetRequest {
    fn command_id(&self) -> u32 {
        0x494D_4C4F // "IMLO"
    }
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageLocationOffsetResponse::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageLocationOffset)
            .map_err(|_| ErrorCode::Invalid)
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug)]
pub struct GetImageLocationOffsetResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub offset: u32,
}

impl MailboxResponseTrait for GetImageLocationOffsetResponse {}

/// GetImageSize
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable, Default)]
pub struct GetImageSizeRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl MailboxRequestTrait for GetImageSizeRequest {
    fn command_id(&self) -> u32 {
        0x494D_535A // "IMSZ"
    }

    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageSizeResponse::try_read_from_bytes(response)
            .map(MailboxResponse::GetImageSize)
            .map_err(|_| ErrorCode::Invalid)
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug)]
pub struct GetImageSizeResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub size: u32,
}

impl MailboxResponseTrait for GetImageSizeResponse {}

/// AuthorizeAndStash
#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct AuthorizeAndStashRequest {
    pub chksum: u32,
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
            chksum: 0,            // Default checksum
            fw_id: [0; 4],        // Default firmware ID
            measurement: [0; 48], // Default measurement hash
            context: [0; 48],     // Default context hash
            flags: 0,             // Default flags
            source: 0,            // Default source
        }
    }
}

impl MailboxRequestTrait for AuthorizeAndStashRequest {
    fn command_id(&self) -> u32 {
        0x4154_5348 // "ATSH"
    }

    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        AuthorizeAndStashResponse::try_read_from_bytes(response)
            .map(MailboxResponse::AuthorizeAndStash)
            .map_err(|_| ErrorCode::Invalid)
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug)]
pub struct AuthorizeAndStashResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub auth_req_result: u32,
}

/// Image is authorized
pub const AUTHORIZED_IMAGE: u32 = 0xDEADC0DE;
/// Image is not authorized
pub const IMAGE_NOT_AUTHORIZED: u32 = 0x21523F21;
/// Image hash mismatch
pub const IMAGE_HASH_MISMATCH: u32 = 0x8BFB95CB;

impl MailboxResponseTrait for AuthorizeAndStashResponse {}
