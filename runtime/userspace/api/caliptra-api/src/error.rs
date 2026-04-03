// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mailbox::MailboxError;
use libtock_platform::ErrorCode;
use ocp_eat::EatError;

pub type CaliptraApiResult<T> = Result<T, CaliptraApiError>;

#[derive(Debug, PartialEq)]
pub enum CaliptraApiError {
    MailboxBusy,
    Mailbox(MailboxError),
    Syscall(ErrorCode),
    InvalidArgument(&'static str),
    InvalidOperation(&'static str),
    AesGcmInvalidDataLength,
    AesGcmInvalidAadLength,
    AesGcmInvalidOperation,
    AesGcmInvalidContext,
    AesGcmTagVerifyFailed,
    AsymAlgoUnsupported,
    InvalidResponse,
    UnprovisionedCsr,
    Eat(EatError),
}
