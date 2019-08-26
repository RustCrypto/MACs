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
#![deny(missing_docs)]

// TODO: replace with `u32::{from_le_bytes, to_le_bytes}` in libcore (1.32+)
extern crate byteorder;
pub extern crate subtle;

#[cfg(feature = "zeroize")]
extern crate zeroize;

use byteorder::{ByteOrder, LE};
use core::cmp::min;
use subtle::{Choice, ConstantTimeEq};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Size of a Poly1305 key
pub const KEY_SIZE: usize = 32;

/// Poly1305 keys (32-bytes)
pub type Key = [u8; KEY_SIZE];

/// Size of the blocks Poly1305 acts upon
pub const BLOCK_SIZE: usize = 16;

/// Poly1305 blocks (16-bytes)
pub type Block = [u8; BLOCK_SIZE];

/// The Poly1305 universal hash function.
///
/// Note that Poly1305 is not a traditional MAC and is single-use only
/// (a.k.a. "one-time authenticator").
///
/// For this reason it doesn't impl the `crypto_mac::Mac` trait.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    leftover: usize,
    buffer: Block,
}

impl Poly1305 {
    /// Initialize Poly1305 with the given key
    pub fn new(key: &Key) -> Poly1305 {
        let mut poly = Poly1305 {
            r: [0u32; 5],
            h: [0u32; 5],
            pad: [0u32; 4],
            leftover: 0,
            buffer: Block::default(),
        };

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        poly.r[0] = (LE::read_u32(&key[0..4])) & 0x3ff_ffff;
        poly.r[1] = (LE::read_u32(&key[3..7]) >> 2) & 0x3ff_ff03;
        poly.r[2] = (LE::read_u32(&key[6..10]) >> 4) & 0x3ff_c0ff;
        poly.r[3] = (LE::read_u32(&key[9..13]) >> 6) & 0x3f0_3fff;
        poly.r[4] = (LE::read_u32(&key[12..16]) >> 8) & 0x00f_ffff;

        poly.pad[0] = LE::read_u32(&key[16..20]);
        poly.pad[1] = LE::read_u32(&key[20..24]);
        poly.pad[2] = LE::read_u32(&key[24..28]);
        poly.pad[3] = LE::read_u32(&key[28..32]);

        poly
    }

    /// Input data into the Poly1305 universal hash function
    pub fn input(&mut self, data: &[u8]) {
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());

            for (i, byte) in m.iter().cloned().enumerate().take(want) {
                self.buffer[self.leftover + i] = byte;
            }

            m = &m[want..];
            self.leftover += want;

            if self.leftover < BLOCK_SIZE {
                return;
            }

            self.block(false);
            self.leftover = 0;
        }

        while m.len() >= BLOCK_SIZE {
            // TODO(tarcieri): avoid a copy here when `TryInto` is available (1.34+)
            // We can avoid copying this data into the buffer, but do for now
            // because it simplifies constant-time assessment.
            self.buffer.copy_from_slice(&m[..BLOCK_SIZE]);
            self.block(false);
            m = &m[BLOCK_SIZE..];
        }

        self.buffer[..m.len()].copy_from_slice(m);
        self.leftover = m.len();
    }

    /// Input data into Poly1305, first padding it to Poly1305's block size
    /// ala the `pad16()` function described in RFC 8439 section 2.8.1:
    /// <https://tools.ietf.org/html/rfc8439#section-2.8.1>
    ///
    /// This is primarily useful for implementing Salsa20 family authenticated
    /// encryption constructions.
    pub fn input_padded(&mut self, data: &[u8]) {
        self.input(data);

        // Pad associated data with `\0` if it's unaligned with the block size
        let unaligned_len = data.len() % BLOCK_SIZE;

        if unaligned_len != 0 {
            let pad = Block::default();
            let pad_len = BLOCK_SIZE - unaligned_len;
            self.input(&pad[..pad_len]);
        }
    }

    /// Process input messages in a chained manner
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.input(data);
        self
    }

    /// Get the hashed output
    pub fn result(mut self) -> Tag {
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;

            for i in (self.leftover + 1)..BLOCK_SIZE {
                self.buffer[i] = 0;
            }

            self.block(true);
        }

        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;

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
        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        // h = mac = (h + pad) % (2^128)
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;

        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;

        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;

        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;

        let mut tag = Block::default();
        LE::write_u32(&mut tag[0..4], h0);
        LE::write_u32(&mut tag[4..8], h1);
        LE::write_u32(&mut tag[8..12], h2);
        LE::write_u32(&mut tag[12..16], h3);

        Tag::new(tag)
    }

    /// Compute a single block of Poly1305 using the internal buffer
    fn block(&mut self, finished: bool) {
        let hibit = if finished { 0 } else { 1 << 24 };

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
        h0 += (LE::read_u32(&self.buffer[0..4])) & 0x3ff_ffff;
        h1 += (LE::read_u32(&self.buffer[3..7]) >> 2) & 0x3ff_ffff;
        h2 += (LE::read_u32(&self.buffer[6..10]) >> 4) & 0x3ff_ffff;
        h3 += (LE::read_u32(&self.buffer[9..13]) >> 6) & 0x3ff_ffff;
        h4 += (LE::read_u32(&self.buffer[12..16]) >> 8) | hibit;

        // h *= r
        let d0 = (u64::from(h0) * u64::from(r0))
            + (u64::from(h1) * u64::from(s4))
            + (u64::from(h2) * u64::from(s3))
            + (u64::from(h3) * u64::from(s2))
            + (u64::from(h4) * u64::from(s1));

        let mut d1 = (u64::from(h0) * u64::from(r1))
            + (u64::from(h1) * u64::from(r0))
            + (u64::from(h2) * u64::from(s4))
            + (u64::from(h3) * u64::from(s3))
            + (u64::from(h4) * u64::from(s2));

        let mut d2 = (u64::from(h0) * u64::from(r2))
            + (u64::from(h1) * u64::from(r1))
            + (u64::from(h2) * u64::from(r0))
            + (u64::from(h3) * u64::from(s4))
            + (u64::from(h4) * u64::from(s3));

        let mut d3 = (u64::from(h0) * u64::from(r3))
            + (u64::from(h1) * u64::from(r2))
            + (u64::from(h2) * u64::from(r1))
            + (u64::from(h3) * u64::from(r0))
            + (u64::from(h4) * u64::from(s4));

        let mut d4 = (u64::from(h0) * u64::from(r4))
            + (u64::from(h1) * u64::from(r3))
            + (u64::from(h2) * u64::from(r2))
            + (u64::from(h3) * u64::from(r1))
            + (u64::from(h4) * u64::from(r0));

        // (partial) h %= p
        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(c);

        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(c);

        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(c);

        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(c);

        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.h.zeroize();
        self.pad.zeroize();
        self.buffer.zeroize();
    }
}

/// Poly1305 authentication tags
pub struct Tag(Block);

impl Tag {
    /// Create a new Poly1305 authentication tag
    fn new(tag: Block) -> Self {
        Tag(tag)
    }
}

impl AsRef<Block> for Tag {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl ConstantTimeEq for Tag {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(other.0.as_ref())
    }
}

impl From<Tag> for Block {
    fn from(tag: Tag) -> Block {
        tag.0
    }
}
