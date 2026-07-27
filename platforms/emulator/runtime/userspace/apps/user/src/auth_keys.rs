// Licensed under the Apache-2.0 license

// NOTE: This file contains a mock authorization anchor for testing purposes. It is
// not secure and must not be used in production environments.
//
// The device stores only the 48-byte SHA-384 hash of the authorized vendor public
// keys, NOT the keys themselves. The public keys travel on the wire with each
// authorized command; the authorizer recomputes SHA-384(ecc_pub_x || ecc_pub_y ||
// mldsa_pub) over the received keys and rejects the command unless it matches this
// anchor, before using those keys to verify the hybrid signature.
//
// This value is produced from the test vendor keypair (TEST_ECC_PRIV_KEY /
// TEST_MLDSA_SEED) by the host signer and is pinned by the
// `anchor_matches_hash_of_public_keys` known-answer test in
// `caliptra-mcu-command-auth-challenge-signer`. If the test keypair changes, update
// this constant from that test's `print_auth_pk_hash_for_test_keypair` output.

/// Length of the authorization public-key hash anchor (SHA-384 digest).
pub const AUTH_PK_HASH_LEN: usize = 48;

/// SHA-384(ecc_pub_x[48] || ecc_pub_y[48] || mldsa_pub[2592]) of the test vendor keypair.
pub const AUTH_PK_HASH: [u8; AUTH_PK_HASH_LEN] = [
    0x29, 0x04, 0x41, 0x6e, 0xf2, 0x71, 0x31, 0x40, 0xd4, 0xa2, 0x21, 0x14, 0x48, 0xa3, 0xa8, 0x42,
    0x73, 0x7b, 0xf1, 0x8c, 0x6f, 0x84, 0x3f, 0x56, 0x5b, 0x5c, 0xe5, 0x35, 0xea, 0x69, 0xef, 0x2a,
    0x8c, 0xc1, 0x14, 0xb1, 0xbe, 0xb2, 0xe6, 0x5f, 0x5f, 0x0f, 0x35, 0x4b, 0x30, 0x9b, 0xed, 0x17,
];
