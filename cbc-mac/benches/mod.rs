#![feature(test)]
extern crate test;

use aes::Aes128;
use cbc_mac::{CbcMac, Mac};
use des::Des;
use test::Bencher;

digest::bench_update!(
    CbcMac::<Aes128>::new(&Default::default());
    cbc_mac_aes128_10 10;
    cbc_mac_aes128_100 100;
    cbc_mac_aes128_1000 1000;
    cbc_mac_aes128_10000 10000;
);

digest::bench_update!(
    CbcMac::<Des>::new(&Default::default());
    daa_10 10;
    daa_100 100;
    daa_1000 1000;
    daa_10000 10000;
);
