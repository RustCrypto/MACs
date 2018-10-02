#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate cmac;
extern crate aes;

bench!(cmac::Cmac::<aes::Aes128>);
