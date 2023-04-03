#![feature(test)]
extern crate test;

use belt_mac::{BeltMac, Mac};
use test::Bencher;
use belt_block::BeltBlock;

digest::bench_update!(
    BeltMac::<BeltBlock>::new(&Default::default());
    belt_mac_10 10;
    belt_mac_100 100;
    belt_mac_1000 1000;
    belt_mac_10000 10000;
);