#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate poly1305;

bench!(poly1305::Poly1305);
