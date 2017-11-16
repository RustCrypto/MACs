use block_cipher_trait::generic_array::typenum::{U8, U16, U32};
use super::Block;

use core::mem;

/// Block doublable over Galois Field.
///
/// This trait is implemented for 64, 128 and 256 bit block sizes.
pub trait Doublable {
    /// Return doubled value of the block.
    ///
    /// If most significant bit of the block equals to zero will return
    /// `block<<1`, otherwise `(block<<1)^C`, where `C` is the non-leading
    /// coefficients of the lexicographically first irreducible degree-b binary
    /// polynomial with the minimal number of ones.
    fn double(self) -> Self;
}

impl Doublable for Block<U8> {
    fn double(self) -> Self {
        let mut val: u64 = unsafe { mem::transmute(self) };
        val = val.to_be();
        val = if val >> 63 == 1 {
            (val << 1) ^ 0b11011
        } else {
            val << 1
        };
        unsafe { mem::transmute(val.to_be()) }
    }
}

#[inline(always)]
fn to_be(val: &mut [u64]) {
    for v in val.iter_mut() {
        *v = v.to_be();
    }
}

impl Doublable for Block<U16> {
    fn double(self) -> Self {
        let mut val: [u64; 2] = unsafe { mem::transmute(self) };
        to_be(&mut val);

        let mut flag = false;

        for v in val.iter_mut().rev() {
            let mut t = *v << 1;
            if flag { t += 1; }

            flag = (*v >> 63) == 1;
            *v = t;
        }

        if flag {
            val[1] ^= 0b10000111;
        }

        to_be(&mut val);
        unsafe { mem::transmute(val) }
    }
}

impl Doublable for Block<U32> {
    fn double(self) -> Self {
        let mut val: [u64; 4] = unsafe { mem::transmute(self) };
        to_be(&mut val);

        let mut flag = false;
        for v in val.iter_mut().rev() {
            let mut t = *v << 1;
            if flag { t += 1; }

            flag = (*v >> 63) == 1;
            *v = t;
        }

        if flag {
            val[3] ^= 0b100_0010_0101;
        }

        to_be(&mut val);
        unsafe { mem::transmute(val) }
    }
}
