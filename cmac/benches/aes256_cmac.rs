#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate aes;
extern crate cmac;

bench!(cmac::Cmac::<aes::Aes256>);
