//! Tests taken from: http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-test.htm
#![no_std]
#[macro_use]
extern crate crypto_mac;
extern crate aes;
extern crate pmac;

use aes::{Aes128, Aes192, Aes256};
use pmac::Pmac;

new_test!(pmac_aes128, "aes128", Pmac<Aes128>);
new_test!(pmac_aes192, "aes192", Pmac<Aes192>);
new_test!(pmac_aes256, "aes256", Pmac<Aes256>);
