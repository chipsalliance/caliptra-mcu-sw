use libtock_platform::{ErrorCode, Syscalls};
use zerocopy::{FromBytes, Immutable, IntoBytes, TryFromBytes};
use libsyscall_caliptra::mailbox::Mailbox;

/// Common trait for Mailbox requests
pub trait MailboxRequestTrait: FromBytes + IntoBytes {
    /// Returns the command ID associated with the request.
    fn command_id(&self) -> u32;

    /// Populates the checksum field for the request.
    fn populate_checksum(&mut self) {
        let mut sum: u32 = self.command_id().to_le_bytes().iter().map(|&b| b as u32).sum();
        let bytes = self.as_mut_bytes();
        sum = sum.wrapping_add(bytes[4..].iter().map(|&b| b as u32).sum::<u32>());
        bytes[0..4].copy_from_slice(&0u32.wrapping_sub(sum).to_le_bytes());
    }

    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode>;
}

/// Enum defining all possible Mailbox Requests
#[derive(Debug)]
pub enum MailboxRequest {
    GetImageLoadAddress(GetImageLoadAddressRequest),
    GetImageLocationOffset(GetImageLocationOffsetRequest),
    GetImageSize(GetImageSizeRequest),
}

impl MailboxRequest {
    fn get_command_id(&self) -> u32 {
        match self {
            MailboxRequest::GetImageLoadAddress(req) => req.command_id(),
            MailboxRequest::GetImageLocationOffset(req) => req.command_id(),
            MailboxRequest::GetImageSize(req) => req.command_id(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            MailboxRequest::GetImageLoadAddress(req) => req.as_bytes(),
            MailboxRequest::GetImageLocationOffset(req) => req.as_bytes(),
            MailboxRequest::GetImageSize(req) => req.as_bytes(),
        }
    }

    fn parse_response(&self, response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        match self {
            MailboxRequest::GetImageLoadAddress(req) => GetImageLoadAddressRequest::parse_response(response),
            MailboxRequest::GetImageLocationOffset(req) => GetImageLocationOffsetRequest::parse_response(response),
            MailboxRequest::GetImageSize(req) => GetImageSizeRequest::parse_response(response),
        }
    }

}

#[derive(Debug)]
pub enum MailboxResponse {
    GetImageLoadAddress(GetImageLoadAddressResponse),
    GetImageLocationOffset(GetImageLocationOffsetResponse),
    GetImageSize(GetImageSizeResponse),
}

impl MailboxResponse {
    fn verify_checksum(&mut self)-> Result<(), ErrorCode> {
        match self {
            MailboxResponse::GetImageLoadAddress(resp) => resp.verify_checksum(),
            MailboxResponse::GetImageLocationOffset(resp) => resp.verify_checksum(),
            MailboxResponse::GetImageSize(resp) => resp.verify_checksum(),
        }
    }
}

/// Trait defining the Mailbox API
pub trait MailboxAPIIntf {
    async fn execute_command(&self, request: &MailboxRequest) -> Result<MailboxResponse, ErrorCode>;
}


/// Trait defining the Mailbox API
pub struct MailboxAPI<S: Syscalls> 
{ 
    syscall: Mailbox<S>,
}

impl <S: Syscalls> MailboxAPI<S> {
    pub fn new() -> Self {
        Self {
            syscall: Mailbox::new(),
        }
    }
 
}

impl<S: Syscalls> MailboxAPIIntf for MailboxAPI<S> {
    
    async fn execute_command(&self, request: &MailboxRequest) -> Result<MailboxResponse, ErrorCode> {

        let mut my_buffer = [0u8; 64];
        let resp = self.syscall.execute(request.get_command_id(), request.as_bytes(), &mut my_buffer).await?;
        let mut response = request.parse_response(&my_buffer[0..resp])?;
        response.verify_checksum()?;

        // return the response
        Ok(response)
        
    }
}



pub trait MailboxResponseTrait : FromBytes + IntoBytes {
    fn verify_checksum(&mut self) -> Result<(), ErrorCode> {
        // verify checksum is correct
        let sum: u32 = self.as_mut_bytes().iter().map(|&b| b as u32).sum();
        if sum == 0 {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }
}



/**************************************************************************
 GetImageLoadAddress
 *************************************************************************/

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageLoadAddressRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl GetImageLoadAddressRequest {
    pub fn new(fw_id: u32) -> Self {
        Self {
            chksum: 0,
            fw_id: fw_id.to_le_bytes(),
        }
    }
}


impl MailboxRequestTrait for GetImageLoadAddressRequest {
    fn command_id(&self) -> u32 {
        0x494D_4C41 // "IMLA"
    }
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageLoadAddressResponse::try_read_from_bytes(response)
            .map(|resp| MailboxResponse::GetImageLoadAddress(resp))
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


/**************************************************************************
 GetImageLocationOffset
 *************************************************************************/

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageLocationOffsetRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl GetImageLocationOffsetRequest {
    pub fn new(fw_id: u32) -> Self {
        Self {
            chksum: 0,
            fw_id: fw_id.to_le_bytes(),
        }
    }
}

impl MailboxRequestTrait for GetImageLocationOffsetRequest {
    fn command_id(&self) -> u32 {
        0x494D_4C4F // "IMLO"
    }
    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageLocationOffsetResponse::try_read_from_bytes(response)
            .map(|resp| MailboxResponse::GetImageLocationOffset(resp))
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

/**************************************************************************
 GetImageSize
 *************************************************************************/

#[repr(C)]
#[derive(FromBytes, IntoBytes, Debug, Immutable)]
pub struct GetImageSizeRequest {
    pub chksum: u32,
    pub fw_id: [u8; 4],
}

impl GetImageSizeRequest {
    pub fn new(fw_id: u32) -> Self {
        Self {
            chksum: 0,
            fw_id: fw_id.to_le_bytes(),
        }
    }
}

impl MailboxRequestTrait for GetImageSizeRequest {
    fn command_id(&self) -> u32 {
        0x494D_535A // "IMSZ"
    }

    fn parse_response(response: &[u8]) -> Result<MailboxResponse, ErrorCode> {
        GetImageSizeResponse::try_read_from_bytes(response)
            .map(|resp| MailboxResponse::GetImageSize(resp))
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
