// Licensed under the Apache-2.0 license

pub const MAX_CERT_COUNT_PER_CHAIN: usize = 4;

// Maximum size of a DER certificate in bytes. Adjust as needed.
pub const MAX_DER_CERT_LENGTH: usize = 1024;

pub const MAX_CERT_CHAIN_DATA_SIZE: usize = MAX_DER_CERT_LENGTH * MAX_CERT_COUNT_PER_CHAIN;

// Maximum size of a certificate portion in bytes. Adjust as needed.
pub const MAX_SPDM_CERT_PORTION_LEN: usize = 512;

// This is a hard-coded test device ID cert for development and testing.
// Refactor out when we have real mechanism to retrieve the certificate chain.
pub static TEST_DEVID_CERT_DER: [u8; 651] = [
    0x30, 0x82, 0x02, 0x87, 0x30, 0x82, 0x02, 0x0e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x3e,
    0xc5, 0xea, 0x53, 0x76, 0x6f, 0x8b, 0x8a, 0x86, 0x16, 0xa5, 0xb8, 0xc4, 0xfc, 0x2b, 0xe3, 0xfc,
    0x8b, 0x06, 0xf3, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x7b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72,
    0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61,
    0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f,
    0x72, 0x70, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x49, 0x54, 0x20,
    0x44, 0x65, 0x70, 0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x35, 0x30, 0x33, 0x32, 0x35, 0x32, 0x32, 0x33, 0x39, 0x34, 0x30, 0x5a, 0x17, 0x0d, 0x33,
    0x35, 0x30, 0x33, 0x32, 0x33, 0x32, 0x32, 0x33, 0x39, 0x34, 0x30, 0x5a, 0x30, 0x7b, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61,
    0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46,
    0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x49, 0x54, 0x20, 0x44, 0x65, 0x70,
    0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
    0x04, 0x03, 0x17, 0x06, 0x8a, 0x01, 0x66, 0xf1, 0x90, 0xb9, 0xf4, 0x90, 0x17, 0x3d, 0xad, 0x24,
    0x78, 0x00, 0x22, 0x04, 0xfc, 0xa4, 0xdd, 0x89, 0x77, 0x06, 0xcf, 0xc3, 0x5a, 0x7a, 0x55, 0x64,
    0xce, 0x81, 0xb1, 0x1c, 0x21, 0x21, 0xe9, 0x35, 0x2c, 0x4a, 0xd4, 0xa4, 0x77, 0x46, 0x58, 0x39,
    0xda, 0x7f, 0x2d, 0x0b, 0xfd, 0xed, 0xb4, 0x6a, 0x85, 0x90, 0x6e, 0xa2, 0x23, 0x57, 0xc0, 0x88,
    0xe2, 0xf6, 0x77, 0x75, 0x20, 0xc9, 0xa9, 0xa2, 0xaf, 0x51, 0x49, 0x35, 0xc4, 0xdd, 0x50, 0x55,
    0x57, 0xf4, 0xdd, 0xe5, 0xcc, 0xae, 0x1a, 0x6b, 0xe9, 0x95, 0x93, 0xbb, 0x19, 0x1d, 0xdb, 0xa0,
    0x8e, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
    0x01, 0x11, 0x33, 0x9d, 0x25, 0xb4, 0x74, 0x07, 0x82, 0xb2, 0x96, 0x99, 0xfc, 0x4b, 0xd7, 0x98,
    0x3c, 0x31, 0x15, 0xfb, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
    0x14, 0x01, 0x11, 0x33, 0x9d, 0x25, 0xb4, 0x74, 0x07, 0x82, 0xb2, 0x96, 0x99, 0xfc, 0x4b, 0xd7,
    0x98, 0x3c, 0x31, 0x15, 0xfb, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
    0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x5d, 0xe0, 0xa5, 0xc9, 0xa0, 0x71, 0x9e,
    0xa4, 0x7d, 0xac, 0xfb, 0xa3, 0x7d, 0x44, 0x4f, 0x88, 0x09, 0x2c, 0xad, 0x4a, 0x8b, 0xa3, 0xd7,
    0x07, 0xf4, 0xc7, 0xcd, 0xe4, 0xf8, 0xe3, 0xaa, 0x42, 0x0b, 0x0a, 0x76, 0x63, 0xea, 0xe2, 0xf2,
    0xa8, 0xf9, 0x56, 0x8f, 0xbf, 0xcb, 0xa2, 0xd3, 0x9f, 0x02, 0x30, 0x05, 0x09, 0xc6, 0x3b, 0xb3,
    0x0d, 0xe2, 0xc1, 0x8c, 0x4a, 0x36, 0x08, 0x44, 0x16, 0xaf, 0xf4, 0x2a, 0x10, 0x07, 0x2d, 0x07,
    0x4a, 0xd0, 0xdd, 0x65, 0x0c, 0x7b, 0x9b, 0xe2, 0x7f, 0xee, 0x2e, 0xd6, 0xef, 0x91, 0x72, 0xbb,
    0x56, 0xb0, 0xf5, 0x9e, 0xef, 0x60, 0x90, 0x51, 0x46, 0x11, 0x45,
];

// This is a hard-coded test device ID cert development and testing.
// Refactor out when we have real mechanism to retrieve the certificate chain.
pub static TEST_ALIAS_CERT_DER: [u8; 719] = [
    0x30, 0x82, 0x02, 0xcb, 0x30, 0x82, 0x02, 0x51, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x36,
    0x94, 0xec, 0x60, 0xdd, 0xa1, 0x77, 0xf3, 0xc8, 0x81, 0x1a, 0x32, 0x95, 0xee, 0x8f, 0xc5, 0x38,
    0x1f, 0xa3, 0x0e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x7b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72,
    0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61,
    0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f,
    0x72, 0x70, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x49, 0x54, 0x20,
    0x44, 0x65, 0x70, 0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x35, 0x30, 0x33, 0x32, 0x35, 0x32, 0x32, 0x34, 0x33, 0x30, 0x34, 0x5a, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x33, 0x32, 0x35, 0x32, 0x32, 0x34, 0x33, 0x30, 0x34, 0x5a, 0x30, 0x7e, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61,
    0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46,
    0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x49, 0x54, 0x20, 0x44, 0x65, 0x70,
    0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0a, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x20, 0x43, 0x65, 0x72, 0x74, 0x30, 0x76, 0x30, 0x10,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    0x03, 0x62, 0x00, 0x04, 0x90, 0xd8, 0xf3, 0xe2, 0xd2, 0x7f, 0x11, 0x7c, 0xb9, 0xd5, 0x34, 0xfb,
    0x33, 0x24, 0x84, 0x03, 0x61, 0x05, 0x6d, 0xd7, 0x89, 0x63, 0x6e, 0x3e, 0xde, 0x83, 0xcd, 0x14,
    0x7c, 0xfc, 0xe3, 0x28, 0x84, 0xbd, 0x17, 0x5b, 0x8d, 0x90, 0x99, 0xac, 0x56, 0xf1, 0x24, 0xe0,
    0x7d, 0x15, 0xc4, 0xc6, 0x76, 0xba, 0xe0, 0xfd, 0xdb, 0x3c, 0x8f, 0x27, 0xa5, 0x07, 0x43, 0x9a,
    0xb7, 0xb8, 0xeb, 0xf5, 0x97, 0xa9, 0x3e, 0xd7, 0x35, 0x10, 0xbc, 0x9f, 0xc1, 0x3c, 0x09, 0x05,
    0x30, 0x4e, 0xb4, 0x71, 0x7d, 0xf2, 0x4a, 0xba, 0x23, 0xa3, 0x70, 0x4a, 0x8a, 0x93, 0x79, 0xdd,
    0xed, 0x9c, 0xef, 0xf7, 0xa3, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
    0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02,
    0x05, 0xe0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
    0x02, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0xed, 0xa5, 0xa2, 0x64, 0x9c, 0xf6, 0x50, 0xb1, 0x7e, 0xa2, 0x30, 0x83,
    0xac, 0x39, 0xb7, 0x54, 0x25, 0x75, 0xd8, 0xa3, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0x01, 0x11, 0x33, 0x9d, 0x25, 0xb4, 0x74, 0x07, 0x82, 0xb2, 0x96,
    0x99, 0xfc, 0x4b, 0xd7, 0x98, 0x3c, 0x31, 0x15, 0xfb, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x1b, 0x44, 0xe1, 0x16,
    0x30, 0x1d, 0x51, 0xbd, 0xd0, 0xce, 0xe4, 0x3a, 0x25, 0x97, 0x57, 0x8f, 0x3b, 0x70, 0x8d, 0x3a,
    0x71, 0x56, 0x55, 0x35, 0x85, 0x71, 0x41, 0x0c, 0x3b, 0xb3, 0x1b, 0xc1, 0x46, 0x4a, 0xa8, 0xfe,
    0xe5, 0x1e, 0x6a, 0xae, 0x4d, 0x5c, 0x6b, 0xcb, 0x6a, 0x5e, 0x38, 0xea, 0x02, 0x31, 0x00, 0x98,
    0xc6, 0xab, 0x2c, 0x43, 0x03, 0x9a, 0xab, 0x12, 0x27, 0x08, 0xbe, 0xea, 0x8d, 0xb3, 0x9c, 0x32,
    0x74, 0x04, 0x3c, 0x8c, 0xe3, 0xab, 0xbc, 0xd5, 0x99, 0xf8, 0x07, 0xaa, 0x11, 0xd4, 0xc0, 0x63,
    0x00, 0x87, 0xd3, 0xc9, 0x6c, 0x5f, 0x38, 0x73, 0x65, 0x8c, 0xa0, 0xb1, 0x75, 0x44, 0x64,
];
