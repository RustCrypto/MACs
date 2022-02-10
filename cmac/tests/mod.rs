use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use des::{TdesEde2, TdesEde3};
use digest::new_resettable_mac_test;
use kuznyechik::Kuznyechik;
use magma::Magma;

// Tests from NIST SP 800-38B:
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
new_resettable_mac_test!(cmac_aes128_nist, "aes128", Cmac<Aes128>);
new_resettable_mac_test!(cmac_aes192_nist, "aes192", Cmac<Aes192>);
new_resettable_mac_test!(cmac_aes256_nist, "aes256", Cmac<Aes256>);

// Tests from CAVP (excluding all 64 KiB vectors for AES-128 except the first one):
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
new_resettable_mac_test!(cmac_aes128_cavp, "cavp_aes128", Cmac<Aes128>, trunc_left);
new_resettable_mac_test!(cmac_aes192_cavp, "cavp_aes192", Cmac<Aes192>, trunc_left);
new_resettable_mac_test!(cmac_aes256_cavp, "cavp_aes256", Cmac<Aes256>, trunc_left);
new_resettable_mac_test!(cmac_tdes2_cavp, "cavp_tdes2", Cmac<TdesEde2>, trunc_left);
new_resettable_mac_test!(cmac_tdes3_cavp, "cavp_tdes3", Cmac<TdesEde3>, trunc_left);

// Tests from Project Wycheproof:
// https://github.com/google/wycheproof
new_resettable_mac_test!(cmac_aes128_wycheproof, "wycheproof-aes128", Cmac<Aes128>);
new_resettable_mac_test!(cmac_aes192_wycheproof, "wycheproof-aes192", Cmac<Aes192>);
new_resettable_mac_test!(cmac_aes256_wycheproof, "wycheproof-aes256", Cmac<Aes256>);

// Test from GOST R 34.13-2015:
// https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
new_resettable_mac_test!(cmac_kuznyechik_gost, "kuznyechik", Cmac<Kuznyechik>);
new_resettable_mac_test!(cmac_magma_gost, "magma", Cmac<Magma>);
