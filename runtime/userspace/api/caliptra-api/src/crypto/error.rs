// Licensed under the Apache-2.0 license

use thiserror_no_std::Error;

use libsyscall_caliptra::mailbox::MailboxError;
use libtock_platform::ErrorCode;

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Mailbox error {:?}", .0)]
    MailboxError(#[from] MailboxError),
    #[error("System call error {:?}", .0)]
    SyscallError(#[from] ErrorCode),
    #[error("Invalid argument: {0}")]
    InvalidArgument(&'static str),
    #[error("Invalid operation: {0}")]
    InvalidOperation(&'static str),
    #[error("Invalid response")]
    InvalidResponse,
}
