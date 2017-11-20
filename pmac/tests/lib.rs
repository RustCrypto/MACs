//! Tests from NIST SP 800-38B:
//! https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
#![no_std]
#[macro_use]
extern crate crypto_mac;
extern crate aesni;
extern crate pmac;

use pmac::Pmac;
use pmac::crypto_mac::dev::{mac_test, Test};
use aesni::{Aes128, Aes192, Aes256};


#[test]
fn pmac_aes128() {
    let tests = new_mac_tests!(
        "aes128/1", "aes128/2", "aes128/3", "aes128/4",
        "aes128/5", "aes128/6", "aes128/7"
    );
    mac_test::<Pmac<Aes128>>(&tests);
}

#[test]
fn pmac_aes192() {
    let tests = new_mac_tests!(
        "aes192/1", "aes192/2", "aes192/3", "aes192/4",
        "aes192/5", "aes192/6", "aes192/7"
    );
    mac_test::<Pmac<Aes192>>(&tests);
}

#[test]
fn pmac_aes256() {
    let tests = new_mac_tests!(
        "aes256/1", "aes256/2", "aes256/3", "aes256/4",
        "aes256/5", "aes256/6", "aes256/7"
    );
    mac_test::<Pmac<Aes256>>(&tests);
}
