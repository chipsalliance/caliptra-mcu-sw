// Licensed under the Apache-2.0 license

pub const MAX_CERT_COUNT_IN_CHAIN: usize = 4;

pub const MAX_DER_CERT_LENGTH: usize = 1024;

pub const MAX_DEVID_CERT_LENGTH: usize = MAX_DER_CERT_LENGTH;

pub const MAX_ALIAS_CERT_LENGTH: usize = 685; // A reference number from Cerberus

pub const MAX_CERT_CHAIN_DATA_SIZE: usize = MAX_DER_CERT_LENGTH * MAX_CERT_COUNT_IN_CHAIN;
