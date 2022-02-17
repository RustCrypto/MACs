//! Generic implementation of [Parallelizable Message Authentication Code (PMAC)][1],
//! otherwise known as OMAC1.
//!
//! # Examples
//! We will use AES-128 block cipher from the [aes](https://docs.rs/aes) crate.
//!
//! To get authentication code:
//!
//! ```rust
//! use aes::Aes128;
//! use pmac::{Pmac, Mac};
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
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use aes::Aes128;
//! # use pmac::{Pmac, Mac};
//! let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//!
//! mac.update(b"input message");
//!
//! # let tag_bytes = mac.clone().finalize().into_bytes();
//! // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
//! mac.verify(&tag_bytes).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/PMAC_(cryptography)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/pmac/0.7.1"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use digest::{self, Mac};

use cipher::{BlockBackend, BlockCipher, BlockClosure, BlockEncryptMut, ParBlocks};
use core::fmt;
use dbl::Dbl;
use digest::{
    block_buffer::Lazy,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::{InnerInit, InnerUser},
    generic_array::{
        typenum::{IsLess, Le, NonZero, Unsigned, U256},
        ArrayLength, GenericArray,
    },
    MacMarker, Output, OutputSizeUser, Reset,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic CMAC instance.
pub type Pmac<C> = CoreWrapper<PmacCore<C, 20>>;

/// Generic PMAC instance
///
/// `LC_SIZE` regulates size of pre-computed table used in PMAC computation.
/// With `LC_SIZE = 20` and for 128-bit block cipher the table is sufficient
/// for 16*2^20 = 16 MiB of input data. For longer messages the `l` value will
/// be computed on the fly from the last table value, which will be a bit less
/// efficient.
// TODO: make LC_SIZE default to 20 on stabilization of
// https://github.com/rust-lang/rust/issues/44580
#[derive(Clone)]
pub struct PmacCore<C, const LC_SIZE: usize>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    state: PmacState<C::BlockSize, LC_SIZE>,
    cipher: C,
}

#[derive(Clone)]
struct PmacState<N, const LC_SIZE: usize>
where
    N: ArrayLength<u8>,
    GenericArray<u8, N>: Dbl,
{
    counter: usize,
    l_inv: Block<Self>,
    l_cache: [Block<Self>; LC_SIZE],
    tag: Block<Self>,
    offset: Block<Self>,
}

impl<N, const LC_SIZE: usize> BlockSizeUser for PmacState<N, LC_SIZE>
where
    N: ArrayLength<u8>,
    GenericArray<u8, N>: Dbl,
{
    type BlockSize = N;
}

impl<N, const LC_SIZE: usize> PmacState<N, LC_SIZE>
where
    N: ArrayLength<u8>,
    GenericArray<u8, N>: Dbl,
{
    #[inline(always)]
    fn next_offset(&mut self) -> &Block<Self> {
        let ntz = self.counter.trailing_zeros() as usize;
        self.counter += 1;
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
        &self.offset
    }
}

#[cfg(feature = "zeroize")]
impl<N, const LC_SIZE: usize> Drop for PmacState<N, LC_SIZE>
where
    N: ArrayLength<u8>,
    GenericArray<u8, N>: Dbl,
{
    fn drop(&mut self) {
        self.counter.zeroize();
        self.l_inv.zeroize();
        self.l_cache.iter_mut().for_each(|c| c.zeroize());
        self.tag.zeroize();
        self.offset.zeroize();
    }
}

impl<C, const LC_SIZE: usize> BlockSizeUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type BlockSize = C::BlockSize;
}

impl<C, const LC_SIZE: usize> OutputSizeUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type OutputSize = C::BlockSize;
}

impl<C, const LC_SIZE: usize> InnerUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type Inner = C;
}

impl<C, const LC_SIZE: usize> MacMarker for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
}

impl<C, const LC_SIZE: usize> Reset for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state.tag = Default::default();
        self.state.offset = Default::default();
        self.state.counter = 1;
    }
}

impl<C, const LC_SIZE: usize> BufferKindUser for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    type BufferKind = Lazy;
}

impl<C, const LC_SIZE: usize> AlgorithmName for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
    Block<C>: Dbl,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pmac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C, const LC_SIZE: usize> fmt::Debug for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
    Block<C>: Dbl,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PmacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C, const LC_SIZE: usize> InnerInit for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline]
    fn inner_init(mut cipher: C) -> Self {
        let mut l = Default::default();
        cipher.encrypt_block_mut(&mut l);
        let l_inv = l.clone().inv_dbl();

        let l_cache = [(); LC_SIZE].map(|_| {
            let next_l = l.clone().dbl();
            core::mem::replace(&mut l, next_l)
        });

        let state = PmacState {
            l_cache,
            l_inv,
            tag: Default::default(),
            offset: Default::default(),
            counter: 1,
        };
        Self { cipher, state }
    }
}

impl<C, const LC_SIZE: usize> UpdateCore for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Ctx<'a, N, const LC_SIZE: usize>
        where
            N: ArrayLength<u8>,
            GenericArray<u8, N>: Dbl,
        {
            state: &'a mut PmacState<N, LC_SIZE>,
            blocks: &'a [Block<Self>],
        }

        impl<'a, N, const LC_SIZE: usize> BlockSizeUser for Ctx<'a, N, LC_SIZE>
        where
            N: ArrayLength<u8>,
            GenericArray<u8, N>: Dbl,
        {
            type BlockSize = N;
        }

        impl<'a, N, const LC_SIZE: usize> BlockClosure for Ctx<'a, N, LC_SIZE>
        where
            N: ArrayLength<u8>,
            GenericArray<u8, N>: Dbl,
        {
            #[inline(always)]
            fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
                let Self { mut blocks, state } = self;
                if B::ParBlocksSize::USIZE > 1 {
                    // TODO: replace with `slice::as_chunks` on stabilization
                    // and migration to const generics
                    let mut iter = blocks.chunks_exact(B::ParBlocksSize::USIZE);
                    for chunk in &mut iter {
                        let mut tmp = ParBlocks::<B>::clone_from_slice(chunk);
                        for block in tmp.iter_mut() {
                            xor(block, state.next_offset());
                        }
                        backend.proc_par_blocks((&mut tmp).into());
                        for t in tmp.iter() {
                            xor(&mut state.tag, t);
                        }
                    }
                    blocks = iter.remainder();
                }

                for block in blocks {
                    let mut block = block.clone();
                    xor(&mut block, state.next_offset());
                    backend.proc_block((&mut block).into());
                    xor(&mut state.tag, &block);
                }
            }
        }

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend_mut(Ctx { blocks, state })
    }
}

impl<C, const LC_SIZE: usize> FixedOutputCore for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    Block<C>: Dbl,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self {
            cipher,
            state: PmacState { tag, l_inv, .. },
        } = self;
        let pos = buffer.get_pos();
        let buf = buffer.pad_with_zeros();
        if pos == buf.len() {
            xor(tag, buf);
            xor(tag, l_inv);
        } else {
            tag[pos] ^= 0x80;
            xor(tag, buf);
        }
        cipher.encrypt_block_b2b_mut(tag, out);
    }
}

#[cfg(feature = "zeroize")]
impl<C, const LC_SIZE: usize> ZeroizeOnDrop for PmacCore<C, LC_SIZE>
where
    C: BlockCipher + BlockEncryptMut + Clone + ZeroizeOnDrop,
    Block<C>: Dbl,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(buf: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
