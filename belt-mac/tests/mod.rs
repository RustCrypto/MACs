//! Test vectors from STB 34.101.31-2020:
//! https://apmi.bsu.by/assets/files/std/belt-spec371.pdf

use belt_mac::BeltMac;
use digest::dev::reset_mac_test;

digest::new_mac_test!(belt_mac_stb, BeltMac, reset_mac_test, trunc_left);
