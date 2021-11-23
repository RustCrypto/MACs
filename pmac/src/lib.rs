//! Generic implementation of [Parallelizable Message Authentication Code (PMAC)][1],
//! otherwise known as OMAC1.
//!
//! # Usage
//! We will use AES-128 block cipher from [aes](https://docs.rs/aes) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! use aes::Aes128;
//! use pmac::{Pmac, Mac};
//! use hex_literal::hex;
//!
//! // Create `Mac` trait implementation, namely PMAC-AES128
//! let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//! mac.update(b"input message");
//!
//! // `result` has type `Output` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.finalize();
//! // To get underlying array use `into_bytes` method, but be careful, since
//! // incorrect use of the tag value may permit timing attacks which defeat
//! // the security provided by the `Output` wrapper
//! let tag_bytes = result.into_bytes();
//! assert_eq!(tag_bytes[..], hex!("b8c60dc25262f0bfd071ffa692d04252")[..]);
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use aes::Aes128;
//! # use pmac::{Pmac, Mac};
//! # use hex_literal::hex;
//! let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//!
//! mac.update(b"input message");
//!
//! let tag_bytes = hex!("b8c60dc25262f0bfd071ffa692d04252");
//! // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
//! mac.verify(&tag_bytes.into()).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/PMAC_(cryptography)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/pmac/0.7.0"
)]
// #![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest;
pub use digest::Mac;

use cipher::{BlockCipher, BlockEncryptMut};

use core::fmt;
use dbl::Dbl;
use digest::{
    block_buffer::Lazy,
    core_api::{Block, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore},
    crypto_common::{AlgorithmName, BlockSizeUser, InnerInit, InnerUser},
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    MacMarker, Output, OutputSizeUser, Reset,
};

/// Generic PMAC instance which operates over bytes.
pub type Pmac<C> = CoreWrapper<PmacCore<C, 20>>;

/// Generic core PMAC instance which operates over blocks.
///
/// The `LC_SIZE` constant determines size of a precomputed lookup table.
/// The [`Pmac`] alias uses value equal to 20, which for 128 bit cipher
/// sufficient for 16*2^20 = 16 MB of input data.
#[derive(Clone)]
pub struct PmacCore<C, const LC_SIZE: usize>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    cipher: C,
    l_cache: [Block<C>; LC_SIZE],
    tag: Block<C>,
    offset: Block<C>,
    counter: usize,
}

impl<C, const LC_SIZE: usize> MacMarker for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
}

impl<C, const LC_SIZE: usize> InnerUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type Inner = C;
}

impl<C, const LC_SIZE: usize> BlockSizeUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type BlockSize = C::BlockSize;
}

impl<C, const LC_SIZE: usize> OutputSizeUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type OutputSize = C::BlockSize;
}

impl<C, const LC_SIZE: usize> BufferKindUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type BufferKind = Lazy;
}

impl<C, const LC_SIZE: usize> InnerInit for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn inner_init(mut cipher: C) -> Self {
        // SAFETY: [Block<C>; LC_SIZE] is equivalent to
        // [[u8; BLOCK_SIZE]; LC_SIZE], so `zeroed` returns
        // a valid value for it
        // TODO: replace with `[(); LC_SIZE].map(..)` or
        // `[[0u8; BLOCK_SIZE]; L]` on MSRV bump
        let mut l_cache: [Block<C>; LC_SIZE] = unsafe {
            core::mem::zeroed()
        };
        if LC_SIZE != 0 {
            cipher.encrypt_block_mut(&mut l_cache[0]);
            for i in 1..LC_SIZE {
                l_cache[i] = l_cache[i - 1].clone().dbl();
            }
        }

        Self {
            cipher,
            l_cache,
            tag: Default::default(),
            offset: Default::default(),
            counter: 1,
        }
    }
}

impl<C, const LC_SIZE: usize> UpdateCore for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // TODO: use parallel encryption, move the branching outside the loop
        for block in blocks {
            let ntz = self.counter.trailing_zeros() as usize;
            let l = if ntz < LC_SIZE {
                self.l_cache[ntz].clone()
            } else {
                let mut block = self.l_cache[LC_SIZE - 1].clone();
                for _ in LC_SIZE - 1..ntz {
                    block = block.dbl();
                }
                block
            };

            xor(&mut self.offset, &l);
            self.counter += 1;
            let mut block = block.clone();
            xor(&mut block, &self.offset);
            self.cipher.encrypt_block_mut(&mut block);
            xor(&mut self.tag, &block);
        }
    }
}

impl<C, const LC_SIZE: usize> FixedOutputCore for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let is_full = pos == Self::BlockSize::USIZE;
        let last_block = buffer.pad_with_zeros();

        if is_full {
            xor(&mut self.tag, last_block);
            let l_inv = self.l_cache[0].clone().inv_dbl();
            xor(&mut self.tag, &l_inv);
        } else {
            last_block[pos] = 0x80;
            xor(&mut self.tag, last_block);
        }

        self.cipher.encrypt_block_b2b_mut(&self.tag, out);
    }
}

impl<C, const LC_SIZE: usize> Reset for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn reset(&mut self) {
        self.tag = Default::default();
        self.offset = Default::default();
        self.counter = 1;
    }
}

impl<C, const LC_SIZE: usize> AlgorithmName for PmacCore<C, LC_SIZE>
where
    C: AlgorithmName + BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pmac<")?;
        C::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C, const LC_SIZE: usize> fmt::Debug for PmacCore<C, LC_SIZE>
where
    C: AlgorithmName + BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PmacCore<")?;
        C::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(buf: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
