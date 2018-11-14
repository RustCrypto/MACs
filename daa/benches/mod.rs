#![feature(test)]
#[macro_use]
extern crate crypto_mac;
extern crate daa;

bench!(daa::Daa);
