//! Carry-less multiplication support.
//!
//! Modern `x86` and `x86_64` CPUs support hardware instructions for
//! carry-less multiplication which are necessary for efficient implementations
//! of GHASH and POLYVAL.

/// Carry-less multiplication trait - allows field arithmetic to be generic
/// across both the `hard` and `soft` backends
pub trait Clmul: Copy {
    /// Performs carry-less multiplication of two 64-bit polynomials over the
    /// finite field GF(2^k).
    fn clmul<I: Into<PseudoOp>>(self, other: Self, imm: I) -> Self;
}

/// Pseudo-Op: selected by bits 4 and 0 of the immediate byte (`imm8`).
///
/// PCLMULQDQ performs carry-less multiplication of two quadwords which are
/// selected from both operands according to the value of `imm8`.
///
/// Bits 4 and 0 of `imm8` are used to select which 64-bit half of each operand
/// to use. Each of the possibilities has a named CLMUL Pseudo-Op, which is
/// represented by this enum.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PseudoOp {
    /// Low-Low: `clmul(a[0..8], b[0..8])`
    PCLMULLQLQDQ = 0x00,

    /// High-Low: `clmul(a[8..16], b[0..8])`
    PCLMULHQLQDQ = 0x01,

    /// Low-High: `clmul(a[0..8], b[8..16])`
    PCLMULLQHQDQ = 0x10,

    /// High-High: `clmul(a[8..16], b[8..16])`
    PCLMULHQHQDQ = 0x11,
}

impl From<u8> for PseudoOp {
    fn from(imm8: u8) -> PseudoOp {
        match imm8 {
            0x00 => PseudoOp::PCLMULLQLQDQ,
            0x01 => PseudoOp::PCLMULHQLQDQ,
            0x10 => PseudoOp::PCLMULLQHQDQ,
            0x11 => PseudoOp::PCLMULHQHQDQ,
            _ => panic!("invalid imm8 value: 0x{:02x}", imm8),
        }
    }
}

impl From<PseudoOp> for u8 {
    fn from(op: PseudoOp) -> u8 {
        op as u8
    }
}
