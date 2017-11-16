//! Tests from NIST SP 800-38B:
//! https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
#![no_std]
#[macro_use]
extern crate crypto_mac;
extern crate aesni;
extern crate cmac;

use cmac::Cmac;
use cmac::crypto_mac::dev::{mac_test, Test};
use aesni::{Aes128, Aes192, Aes256};


#[test]
fn cmac_aes128() {
    let tests = new_mac_tests!("aes128/1", "aes128/2", "aes128/3", "aes128/4");
    mac_test::<Cmac<Aes128>>(&tests);
}

#[test]
fn cmac_aes192() {
    let tests = new_mac_tests!("aes192/1", "aes192/2", "aes192/3", "aes192/4");
    mac_test::<Cmac<Aes192>>(&tests);
}

#[test]
fn cmac_aes256() {
    let tests = new_mac_tests!("aes256/1", "aes256/2", "aes256/3", "aes256/4");
    mac_test::<Cmac<Aes256>>(&tests);
}
