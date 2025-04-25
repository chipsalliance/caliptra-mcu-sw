// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mailbox::MailboxError;
use libtock_platform::ErrorCode;

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug)]
pub enum CryptoError {
    MailboxError(MailboxError),
    SyscallError(ErrorCode),
    InvalidArgument(&'static str),
    InvalidOperation(&'static str),
    InvalidResponse,
}
