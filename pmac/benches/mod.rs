#![feature(test)]
extern crate test;

use aes::{Aes128, Aes256};
use pmac::{Mac, Pmac};
use test::Bencher;

digest::bench_update!(
    Pmac::<Aes128>::new(&Default::default());
    pmac_aes128_10 10;
    pmac_aes128_100 100;
    pmac_aes128_1000 1000;
    pmac_aes128_10000 10000;
);

digest::bench_update!(
    Pmac::<Aes256>::new(&Default::default());
    pmac_aes256_10 10;
    pmac_aes256_100 100;
    pmac_aes256_1000 1000;
    pmac_aes256_10000 10000;
);
