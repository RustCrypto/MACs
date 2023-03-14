use aes::Aes128;
use cmac::Cmac;
use digest::new_resettable_mac_test;

// Tests from CAVP (excluding all 64 KiB vectors for AES-128 except the first one):
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
//
// Test vectors in this file use 65 KiB of data, so they are excluded from published packages.
new_resettable_mac_test!(cmac_aes128_cavp, "cavp_aes128_large", Cmac<Aes128>, trunc_left);
