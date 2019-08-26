//! Software emulation support for CLMUL hardware intrinsics.
//!
//! WARNING: Not constant time! Should be made constant-time or disabled by default.

// TODO(tarcieri): performance-oriented constant-time implementation
// See: <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c>

use super::Backend;
use byteorder::{ByteOrder, LE};
use core::ops::BitXor;
use field::clmul::{self, Clmul};
use Block;

/// 2 x `u64` values emulating an XMM register
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U64x2([u64; 2]);

impl From<Block> for U64x2 {
    fn from(bytes: Block) -> U64x2 {
        let mut u64x2 = [0u64; 2];
        LE::read_u64_into(&bytes, &mut u64x2);
        U64x2(u64x2)
    }
}

impl From<U64x2> for Block {
    fn from(u64x2: U64x2) -> Block {
        let x: u128 = u64x2.into();
        let mut result = Block::default();
        LE::write_u128(&mut result, x);
        result
    }
}

impl From<u128> for U64x2 {
    fn from(x: u128) -> U64x2 {
        let lo = (x & 0xFFFF_FFFFF) as u64;
        let hi = (x >> 64) as u64;
        U64x2([lo, hi])
    }
}

impl From<U64x2> for u128 {
    fn from(u64x2: U64x2) -> u128 {
        u128::from(u64x2.0[0]) | (u128::from(u64x2.0[1]) << 64)
    }
}

impl BitXor for U64x2 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        U64x2([self.0[0] ^ rhs.0[0], self.0[1] ^ rhs.0[1]])
    }
}

impl Clmul for U64x2 {
    fn clmul<I>(self, other: Self, imm: I) -> Self
    where
        I: Into<clmul::PseudoOp>,
    {
        let (a, b) = match imm.into() {
            clmul::PseudoOp::PCLMULLQLQDQ => (self.0[0], other.0[0]),
            clmul::PseudoOp::PCLMULHQLQDQ => (self.0[1], other.0[0]),
            clmul::PseudoOp::PCLMULLQHQDQ => (self.0[0], other.0[1]),
            clmul::PseudoOp::PCLMULHQHQDQ => (self.0[1], other.0[1]),
        };

        let mut result = [0u64; 2];

        for i in 0..64 {
            if b & (1 << i) != 0 {
                result[1] ^= a;
            }

            result[0] >>= 1;

            if result[1] & 1 != 0 {
                result[0] ^= 1 << 63;
            }

            result[1] >>= 1;
        }

        U64x2(result)
    }
}

impl Backend for U64x2 {
    fn shuffle(self) -> Self {
        U64x2([self.0[1], self.0[0]])
    }

    fn shl64(self) -> Self {
        U64x2([0, self.0[0]])
    }

    fn shr64(self) -> Self {
        U64x2([self.0[1], 0])
    }
}
