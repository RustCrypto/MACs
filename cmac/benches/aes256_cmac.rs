#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate cmac;
extern crate aesni;

bench!(cmac::Cmac::<aesni::Aes256>, 32);
