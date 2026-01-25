#![feature(test)]
extern crate test;

use core::hint::black_box;
use kmac::{KeyInit, Kmac128, Kmac256, Mac};
use test::Bencher;

#[macro_export]
macro_rules! bench_full {
    (
        $init:expr;
        $($name:ident $bs:expr;)*
    ) => {
        $(
            #[bench]
            fn $name(b: &mut Bencher) {
                let data = [0; $bs];

                b.iter(|| {
                    let mut d = $init;
                    digest::Update::update(&mut d, black_box(&data[..]));
                    black_box(d.finalize());
                });

                b.bytes = $bs;
            }
        )*
    };
}

bench_full!(
    Kmac128::new(black_box(&Default::default()));
    kmac128_10 10;
    kmac128_100 100;
    kmac128_1000 1000;
    kmac128_10000 10000;
);

bench_full!(
    Kmac256::new(black_box(&Default::default()));
    kmac256_10 10;
    kmac256_100 100;
    kmac256_1000 1000;
    kmac256_10000 10000;
);

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
