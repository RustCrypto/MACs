#![feature(test)]
extern crate test;

use aes::Aes128;
use des::Des;
use retail_mac::{KeyInit, RetailMac};
use test::Bencher;

digest::bench_update!(
    RetailMac::<Aes128>::new(&Default::default());
    retail_mac_aes128_10 10;
    retail_mac_aes128_100 100;
    retail_mac_aes128_1000 1000;
    retail_mac_aes128_10000 10000;
);

digest::bench_update!(
    RetailMac::<Des>::new(&Default::default());
    retail_mac_des_10 10;
    retail_mac_des_100 100;
    retail_mac_des_1000 1000;
    retail_mac_des_10000 10000;
);
