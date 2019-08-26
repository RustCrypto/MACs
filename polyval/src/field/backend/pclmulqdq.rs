//! Support for the PCLMULQDQ CPU intrinsic on `x86` and `x86_64` target
//! architectures.

// The code below uses `loadu`/`storeu` to support unaligned loads/stores
#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::Backend;
use core::ops::BitXor;
use field::clmul::{self, Clmul};
use Block;

/// Wrapper for `__m128i` - a 128-bit XMM register (SSE2)
#[repr(align(16))]
#[derive(Copy, Clone)]
pub struct M128i(__m128i);

impl From<Block> for M128i {
    fn from(bytes: Block) -> M128i {
        M128i(unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) })
    }
}

impl From<M128i> for Block {
    fn from(xmm: M128i) -> Block {
        let mut result = Block::default();

        unsafe {
            _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, xmm.0);
        }

        result
    }
}

impl From<u128> for M128i {
    fn from(x: u128) -> M128i {
        M128i(unsafe { _mm_loadu_si128(&x as *const u128 as *const __m128i) })
    }
}

impl BitXor for M128i {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        M128i(unsafe { xor(self.0, rhs.0) })
    }
}

impl Clmul for M128i {
    fn clmul<I>(self, rhs: Self, imm: I) -> Self
    where
        I: Into<clmul::PseudoOp>,
    {
        M128i(unsafe { pclmulqdq(self.0, rhs.0, imm.into()) })
    }
}

impl Backend for M128i {
    fn shuffle(self) -> Self {
        M128i(unsafe { shufpd1(self.0) })
    }

    fn shl64(self) -> Self {
        M128i(unsafe { pslldq8(self.0) })
    }

    fn shr64(self) -> Self {
        M128i(unsafe { psrldq8(self.0) })
    }
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn shufpd1(a: __m128i) -> __m128i {
    let a = _mm_castsi128_pd(a);
    _mm_castpd_si128(_mm_shuffle_pd(a, a, 1))
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn pslldq8(a: __m128i) -> __m128i {
    _mm_bslli_si128(a, 8)
}

#[target_feature(enable = "sse2", enable = "sse4.1")]
unsafe fn psrldq8(a: __m128i) -> __m128i {
    _mm_bsrli_si128(a, 8)
}

// TODO(tarcieri): _mm256_clmulepi64_epi128 (vpclmulqdq)
#[target_feature(enable = "pclmulqdq", enable = "sse2", enable = "sse4.1")]
unsafe fn pclmulqdq(a: __m128i, b: __m128i, op: clmul::PseudoOp) -> __m128i {
    match op {
        clmul::PseudoOp::PCLMULLQLQDQ => _mm_clmulepi64_si128(a, b, 0x00),
        clmul::PseudoOp::PCLMULHQLQDQ => _mm_clmulepi64_si128(a, b, 0x01),
        clmul::PseudoOp::PCLMULLQHQDQ => _mm_clmulepi64_si128(a, b, 0x10),
        clmul::PseudoOp::PCLMULHQHQDQ => _mm_clmulepi64_si128(a, b, 0x11),
    }
}
