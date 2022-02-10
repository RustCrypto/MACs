#![feature(test)]
extern crate test;

use aes::{Aes128, Aes256};
use cmac::{Cmac, Mac};
use kuznyechik::Kuznyechik;
use test::Bencher;

digest::bench_update!(
    Cmac::<Aes128>::new(&Default::default());
    cmac_aes128_10 10;
    cmac_aes128_100 100;
    cmac_aes128_1000 1000;
    cmac_aes128_10000 10000;
);

digest::bench_update!(
    Cmac::<Aes256>::new(&Default::default());
    cmac_aes256_10 10;
    cmac_aes256_100 100;
    cmac_aes256_1000 1000;
    cmac_aes256_10000 10000;
);

digest::bench_update!(
    Cmac::<Kuznyechik>::new(&Default::default());
    cmac_kuznyechik_10 10;
    cmac_kuznyechik_100 100;
    cmac_kuznyechik_1000 1000;
    cmac_kuznyechik_10000 10000;
);
