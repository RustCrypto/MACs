//! The Poly1305 universal hash function and message authentication code

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// This code originates from the rust-crypto project:
// <https://github.com/DaGenix/rust-crypto>
//
// ...and was originally a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

pub extern crate crypto_mac;

// TODO: replace with `u32::{from_le_bytes, to_le_bytes}` in libcore (1.32+)
extern crate byte_tools;

use byte_tools::{read_u32_le, write_u32_le};
use core::cmp::min;
use crypto_mac::generic_array::{
    typenum::{U16, U32},
    GenericArray,
};
pub use crypto_mac::{Mac, MacResult};

#[derive(Clone, Copy)]
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    leftover: usize,
    buffer: [u8; 16],
    finalized: bool,
}

impl Mac for Poly1305 {
    type OutputSize = U16;
    type KeySize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Poly1305 {
        let mut poly = Poly1305 {
            r: [0u32; 5],
            h: [0u32; 5],
            pad: [0u32; 4],
            leftover: 0,
            buffer: [0u8; 16],
            finalized: false,
        };

        let key = key.as_slice();

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        poly.r[0] = (read_u32_le(&key[0..4])) & 0x3ffffff;
        poly.r[1] = (read_u32_le(&key[3..7]) >> 2) & 0x3ffff03;
        poly.r[2] = (read_u32_le(&key[6..10]) >> 4) & 0x3ffc0ff;
        poly.r[3] = (read_u32_le(&key[9..13]) >> 6) & 0x3f03fff;
        poly.r[4] = (read_u32_le(&key[12..16]) >> 8) & 0x00fffff;

        poly.pad[0] = read_u32_le(&key[16..20]);
        poly.pad[1] = read_u32_le(&key[20..24]);
        poly.pad[2] = read_u32_le(&key[24..28]);
        poly.pad[3] = read_u32_le(&key[28..32]);

        poly
    }

    #[inline]
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finalized);
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());
            for i in 0..want {
                self.buffer[self.leftover + i] = m[i];
            }
            m = &m[want..];
            self.leftover += want;

            if self.leftover < 16 {
                return;
            }

            // self.block(self.buffer[..]);
            let tmp = self.buffer;
            self.block(&tmp);

            self.leftover = 0;
        }

        while m.len() >= 16 {
            self.block(&m[0..16]);
            m = &m[16..];
        }

        for i in 0..m.len() {
            self.buffer[i] = m[i];
        }
        self.leftover = m.len();
    }

    fn result(mut self) -> MacResult<Self::OutputSize> {
        let mut mac = GenericArray::default();
        self.raw_result(mac.as_mut());
        MacResult::new(mac)
    }

    fn reset(&mut self) {
        self.h = [0u32; 5];
        self.leftover = 0;
        self.finalized = false;
    }
}

impl Poly1305 {
    fn block(&mut self, m: &[u8]) {
        let hibit: u32 = if self.finalized { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (read_u32_le(&m[0..4])) & 0x3ffffff;
        h1 += (read_u32_le(&m[3..7]) >> 2) & 0x3ffffff;
        h2 += (read_u32_le(&m[6..10]) >> 4) & 0x3ffffff;
        h3 += (read_u32_le(&m[9..13]) >> 6) & 0x3ffffff;
        h4 += (read_u32_le(&m[12..16]) >> 8) | hibit;

        // h *= r
        let d0 = (h0 as u64 * r0 as u64)
            + (h1 as u64 * s4 as u64)
            + (h2 as u64 * s3 as u64)
            + (h3 as u64 * s2 as u64)
            + (h4 as u64 * s1 as u64);

        let mut d1 = (h0 as u64 * r1 as u64)
            + (h1 as u64 * r0 as u64)
            + (h2 as u64 * s4 as u64)
            + (h3 as u64 * s3 as u64)
            + (h4 as u64 * s2 as u64);

        let mut d2 = (h0 as u64 * r2 as u64)
            + (h1 as u64 * r1 as u64)
            + (h2 as u64 * r0 as u64)
            + (h3 as u64 * s4 as u64)
            + (h4 as u64 * s3 as u64);

        let mut d3 = (h0 as u64 * r3 as u64)
            + (h1 as u64 * r2 as u64)
            + (h2 as u64 * r1 as u64)
            + (h3 as u64 * r0 as u64)
            + (h4 as u64 * s4 as u64);

        let mut d4 = (h0 as u64 * r4 as u64)
            + (h1 as u64 * r3 as u64)
            + (h2 as u64 * r2 as u64)
            + (h3 as u64 * r1 as u64)
            + (h4 as u64 * r0 as u64);

        // (partial) h %= p
        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ffffff;
        d1 += c as u64;

        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ffffff;
        d2 += c as u64;

        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ffffff;
        d3 += c as u64;

        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ffffff;
        d4 += c as u64;

        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ffffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 = h0 & 0x3ffffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    fn finish(&mut self) {
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for i in self.leftover + 1..16 {
                self.buffer[i] = 0;
            }
            self.finalized = true;
            let tmp = self.buffer;
            self.block(&tmp);
        }

        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 = h1 & 0x3ffffff;
        h2 += c;

        c = h2 >> 26;
        h2 = h2 & 0x3ffffff;
        h3 += c;

        c = h3 >> 26;
        h3 = h3 & 0x3ffffff;
        h4 += c;

        c = h4 >> 26;
        h4 = h4 & 0x3ffffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 = h0 & 0x3ffffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;

        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

        // h = mac = (h + pad) % (2^128)
        let mut f: u64;
        f = h0 as u64 + self.pad[0] as u64;
        h0 = f as u32;

        f = h1 as u64 + self.pad[1] as u64 + (f >> 32);
        h1 = f as u32;

        f = h2 as u64 + self.pad[2] as u64 + (f >> 32);
        h2 = f as u32;

        f = h3 as u64 + self.pad[3] as u64 + (f >> 32);
        h3 = f as u32;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        assert!(output.len() >= 16);
        if !self.finalized {
            self.finish();
        }
        write_u32_le(&mut output[0..4], self.h[0]);
        write_u32_le(&mut output[4..8], self.h[1]);
        write_u32_le(&mut output[8..12], self.h[2]);
        write_u32_le(&mut output[12..16], self.h[3]);
    }
}
