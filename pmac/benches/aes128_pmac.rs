#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate aes;
extern crate pmac;

bench!(pmac::Pmac::<aes::Aes128>);
