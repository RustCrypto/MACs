//! Tests from Project Wycheproof:
//! https://github.com/google/wycheproof
#![no_std]
use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use crypto_mac::new_trunc_test;

new_trunc_test!(wycheproof_cmac_aes128, "wycheproof-aes128", Cmac<Aes128>);
new_trunc_test!(wycheproof_cmac_aes192, "wycheproof-aes192", Cmac<Aes192>);
new_trunc_test!(wycheproof_cmac_aes256, "wycheproof-aes256", Cmac<Aes256>);
