#![feature(test)]
extern crate test;

use core::hint::black_box;
use kmac::{KeyInit, Kmac128, Kmac256};
use test::Bencher;

digest::bench_update!(
    Kmac128::new(black_box(&Default::default()));
    kmac128_update_10 10;
    kmac128_update_100 100;
    kmac128_update_1000 1000;
    kmac128_update_10000 10000;
);

digest::bench_update!(
    Kmac256::new(black_box(&Default::default()));
    kmac256_update_10 10;
    kmac256_update_100 100;
    kmac256_update_1000 1000;
    kmac256_update_10000 10000;
);
