#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate pmac;
extern crate aes;

bench!(pmac::Pmac::<aes::Aes256>);
