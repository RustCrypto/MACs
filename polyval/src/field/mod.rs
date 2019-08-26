//! Implementation of POLYVAL's finite field.
//!
//! From [RFC 8452 Section 3] which defines POLYVAL for use in AES-GCM_SIV:
//!
//! > "POLYVAL, like GHASH (the authenticator in AES-GCM; ...), operates in a
//! > binary field of size 2^128.  The field is defined by the irreducible
//! > polynomial x^128 + x^127 + x^126 + x^121 + 1."
//!
//! This implementation provides multiplication over GF(2^128) optimized using
//! Shay Gueron's PCLMULQDQ-based techniques.
//!
//! For more information on how these techniques work, see:
//! <https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html>
//!
//! [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3

pub mod backend;
pub mod clmul;

use self::backend::Backend;
use super::Block;
use core::ops::{Add, Mul};

/// Size of GF(2^128) in bytes (16-bytes).
pub const FIELD_SIZE: usize = 16;

/// Mask value used when performing Montgomery fast reduction.
/// This corresponds to POLYVAL's polynomial with the highest bit unset.
///
/// See: <https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf>
const MASK: u128 = 1 << 127 | 1 << 126 | 1 << 121 | 1;

/// POLYVAL field element.
#[derive(Copy, Clone)]
pub(crate) struct Element<B: Backend>(B);

impl<B: Backend> Element<B> {
    /// Load a `FieldElement` from its bytestring representation.
    pub fn from_bytes(bytes: Block) -> Self {
        Element(bytes.into())
    }

    /// Serialize this `FieldElement` as a bytestring.
    pub fn to_bytes(self) -> Block {
        self.0.into()
    }

    /// Fast reduction modulo x^128 + x^127 + x^126 +x^121 + 1 (Gueron 2012)
    /// Algorithm 4: "Montgomery reduction"
    fn reduce(self) -> Self {
        let mask = B::from(MASK);
        let a = mask.clmul(self.0, 0x01);
        let b = self.0.shuffle() ^ a;
        let c = mask.clmul(b, 0x01);
        let d = b.shuffle() ^ c;
        Element(d)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<B: Backend> Add for Element<B> {
    type Output = Self;

    /// Adds two POLYVAL field elements.
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The sum of any two elements in the field is the result of XORing them."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    fn add(self, rhs: Self) -> Self {
        Element(self.0 ^ rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<B: Backend> Mul for Element<B> {
    type Output = Self;

    /// Computes POLYVAL multiplication over GF(2^128).
    ///
    /// From [RFC 8452 Section 3]:
    ///
    /// > "The product of any two elements is calculated using standard
    /// > (binary) polynomial multiplication followed by reduction modulo the
    /// > irreducible polynomial."
    ///
    /// [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
    fn mul(self, rhs: Self) -> Self {
        let t1 = self.0.clmul(rhs.0, 0x00);
        let t2 = self.0.clmul(rhs.0, 0x01);
        let t3 = self.0.clmul(rhs.0, 0x10);
        let t4 = self.0.clmul(rhs.0, 0x11);
        let t5 = t2 ^ t3;
        Element(t4 ^ t5.shr64()) + Element(t1 ^ t5.shl64()).reduce()
    }
}

impl<B: Backend> From<B> for Element<B> {
    fn from(element: B) -> Element<B> {
        Element(element)
    }
}
