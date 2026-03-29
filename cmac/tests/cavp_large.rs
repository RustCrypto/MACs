//! Tests from CAVP (excluding all 64 KiB vectors for AES-128 except the first one):
//! <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES>
//!
//! Test vectors in this file use 64 KiB of data, so they are excluded from published packages.

use aes::Aes128;
use cmac::Cmac;
use digest::dev::reset_mac_test;

digest::new_mac_test!(
    cmac_aes128_cavp_large,
    Cmac<Aes128>,
    reset_mac_test,
    trunc_left,
);
