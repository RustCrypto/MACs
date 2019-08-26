//! **POLYVAL** is a GHASH-like universal hash over GF(2^128) useful for
//! implementing [AES-GCM-SIV] or [AES-GCM/GMAC].
//!
//! From [RFC 8452 Section 3] which defines POLYVAL for use in AES-GCM_SIV:
//!
//! > "POLYVAL, like GHASH (the authenticator in AES-GCM; ...), operates in a
//! > binary field of size 2^128.  The field is defined by the irreducible
//! > polynomial x^128 + x^127 + x^126 + x^121 + 1."
//!
//! By multiplying (in the finite field sense) a sequence of 128-bit blocks of
//! input data data by a field element `H`, POLYVAL can be used to authenticate
//! the message sequence as powers (in the finite field sense) of `H`.
//!
//! ## Requirements
//!
//! - Rust 1.32.0 or newer
//! - `RUSTFLAGS` with `-Ctarget-cpu` and `-Ctarget-feature`:
//!   - x86(-64) CPU: `target-cpu=sandybridge` or newer
//!   - SSE2 + SSE4.1: `target-feature=+sse2,+sse4.1`
//!
//! An **INSECURE** (variable timing) portable implementation is gated behind
//! the `insecure-soft` cargo feature. Use of this implementation is
//! **NOT RECOMMENDED** and may potentially leak the POLYVAL key!
//!
//! ## Relationship to GHASH
//!
//! POLYVAL can be thought of as the little endian equivalent of GHASH, which
//! affords it a small performance advantage over GHASH when used on little
//! endian architectures.
//!
//! It has also been designed so it can also be used to compute GHASH and with
//! it GMAC, the Message Authentication Code (MAC) used by AES-GCM.
//!
//! From [RFC 8452 Appendix A]:
//!
//! > "GHASH and POLYVAL both operate in GF(2^128), although with different
//! > irreducible polynomials: POLYVAL works modulo x^128 + x^127 + x^126 +
//! > x^121 + 1 and GHASH works modulo x^128 + x^7 + x^2 + x + 1.  Note
//! > that these irreducible polynomials are the 'reverse' of each other."
//!
//! [AES-GCM-SIV]: https://en.wikipedia.org/wiki/AES-GCM-SIV
//! [AES-GCM/GMAC]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
//! [RFC 8452 Section 3]: https://tools.ietf.org/html/rfc8452#section-3
//! [RFC 8452 Appendix A]: https://tools.ietf.org/html/rfc8452#appendix-A

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(missing_docs)]

// TODO: replace with `u64::from_le_bytes`/`u128::to_le_bytes` in libcore (1.32+)
#[cfg(feature = "insecure-soft")]
extern crate byteorder;
pub extern crate subtle;

pub mod field;
pub mod tag;

use self::field::Element;
pub use self::tag::Tag;

// TODO(tarcieri): runtime selection of CLMUL vs soft backend when both are available
use self::field::backend::M128i;

/// Size of a POLYVAL block (128-bits)
pub const BLOCK_SIZE: usize = 16;

/// POLYVAL blocks (16-bytes)
pub type Block = [u8; BLOCK_SIZE];

/// **POLYVAL**: GHASH-like universal hash over GF(2^128).
#[allow(non_snake_case)]
#[derive(Clone)]
#[repr(align(16))]
pub struct Polyval {
    /// GF(2^128) field element input blocks are multiplied by
    H: Element<M128i>,

    /// Field element representing the computed universal hash
    S: Element<M128i>,
}

impl Polyval {
    /// Initialize POLYVAL with the given `H` field element
    pub fn new(h: Block) -> Self {
        Self {
            H: Element::from_bytes(h),
            S: Element::from_bytes(Block::default()),
        }
    }

    /// Input a field element `X` to be authenticated into POLYVAL.
    pub fn input_block(&mut self, x: Block) {
        // "The sum of any two elements in the field is the result of XORing them."
        // -- RFC 8452 Section 3
        let sum = self.S + Element::from_bytes(x);
        self.S = sum * self.H;
    }

    /// Input data into POLYVAL, first padding it to the block size
    /// ala the `right_pad_to_multiple_of_16_bytes()` function described in
    /// RFC 8452 Section 4:
    /// <https://tools.ietf.org/html/rfc8452#section-4>
    pub fn input_padded(&mut self, data: &[u8]) {
        for chunk in data.chunks(BLOCK_SIZE) {
            if chunk.len() == BLOCK_SIZE {
                // TODO(tarcieri): replace with `TryInto` in Rust 1.34+
                self.input_block(unsafe { *(chunk.as_ptr() as *const Block) });
            } else {
                let mut padded_block = [0u8; BLOCK_SIZE];
                padded_block[..chunk.len()].copy_from_slice(chunk);
                self.input_block(padded_block);
            }
        }
    }

    /// Process input blocks in a chained manner
    pub fn chain_block(mut self, x: Block) -> Self {
        self.input_block(x);
        self
    }

    /// Get POLYVAL result (i.e. computed `S` field element)
    pub fn result(self) -> Tag {
        Tag::new(self.S.to_bytes())
    }
}
