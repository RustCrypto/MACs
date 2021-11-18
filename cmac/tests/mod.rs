use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use digest::new_resettable_mac_test;

// Tests from NIST SP 800-38B:
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
new_resettable_mac_test!(nist_cmac_aes128, "aes128", Cmac<Aes128>);
new_resettable_mac_test!(nist_cmac_aes192, "aes192", Cmac<Aes192>);
new_resettable_mac_test!(nist_cmac_aes256, "aes256", Cmac<Aes256>);

// Tests from Project Wycheproof:
// https://github.com/google/wycheproof
new_resettable_mac_test!(wycheproof_cmac_aes128, "wycheproof-aes128", Cmac<Aes128>);
new_resettable_mac_test!(wycheproof_cmac_aes192, "wycheproof-aes192", Cmac<Aes192>);
new_resettable_mac_test!(wycheproof_cmac_aes256, "wycheproof-aes256", Cmac<Aes256>);

// Test vectors from GOST R 34.13-2015:
// https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
new_resettable_mac_test!(
    gost_cmac_kuznyechik,
    "kuznyechik",
    Cmac<kuznyechik::Kuznyechik>
);
new_resettable_mac_test!(gost_cmac_magma, "magma", Cmac<magma::Magma>);
