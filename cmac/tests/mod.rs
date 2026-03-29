//! Test vectors.

use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use des::{TdesEde2, TdesEde3};
use digest::{dev::reset_mac_test, new_mac_test};
use kuznyechik::Kuznyechik;
use magma::Magma;

// Tests from NIST SP 800-38B:
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
new_mac_test!(cmac_aes128_nist, Cmac<Aes128>, reset_mac_test);
new_mac_test!(cmac_aes192_nist, Cmac<Aes192>, reset_mac_test);
new_mac_test!(cmac_aes256_nist, Cmac<Aes256>, reset_mac_test);

// Tests from CAVP (excluding all 64 KiB vectors for AES-128 except the first one):
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
new_mac_test!(cmac_aes128_cavp, Cmac<Aes128>, reset_mac_test, trunc_left);
new_mac_test!(cmac_aes192_cavp, Cmac<Aes192>, reset_mac_test, trunc_left);
new_mac_test!(cmac_aes256_cavp, Cmac<Aes256>, reset_mac_test, trunc_left);
new_mac_test!(cmac_tdes2_cavp, Cmac<TdesEde2>, reset_mac_test, trunc_left);
new_mac_test!(cmac_tdes3_cavp, Cmac<TdesEde3>, reset_mac_test, trunc_left);

// Tests from Project Wycheproof:
// https://github.com/google/wycheproof
new_mac_test!(cmac_aes128_wycheproof, Cmac<Aes128>, reset_mac_test);
new_mac_test!(cmac_aes192_wycheproof, Cmac<Aes192>, reset_mac_test);
new_mac_test!(cmac_aes256_wycheproof, Cmac<Aes256>, reset_mac_test);

// Test from GOST R 34.13-2015:
// https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
new_mac_test!(cmac_kuznyechik_gost, Cmac<Kuznyechik>, reset_mac_test);
new_mac_test!(cmac_magma_gost, Cmac<Magma>, reset_mac_test);
