#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate pmac;
extern crate aesni;

bench!(pmac::Pmac::<aesni::Aes256>);
