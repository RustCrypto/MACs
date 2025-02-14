#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, KeyInit, Mac};

use belt_block::BeltBlock;
use cipher::{BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt};
use core::fmt;
use digest::{
    array::{
        typenum::{IsLess, Le, NonZero, U256},
        Array, ArraySize,
    },
    block_buffer::Lazy,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    MacMarker, Output, OutputSizeUser, Reset,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic BeltMac instance.
pub type BeltMac<C = BeltBlock> = CoreWrapper<BeltMacCore<C>>;

#[derive(Clone)]
/// Generic core BeltMac instance, which operates over blocks.
pub struct BeltMacCore<C = BeltBlock>
where
    C: BlockCipherEncrypt + Clone,
{
    cipher: C,
    state: Block<C>,
    r: Block<C>,
}

impl<C> BlockSizeUser for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerUser for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type Inner = C;
}

impl<C> MacMarker for BeltMacCore<C> where C: BlockCipherEncrypt + Clone {}

impl<C> InnerInit for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let state = Default::default();
        let mut r = Default::default();
        cipher.encrypt_block(&mut r);
        Self { cipher, state, r }
    }
}

impl<C> BufferKindUser for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type BufferKind = Lazy;
}

impl<C> UpdateCore for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Closure<'a, N: BlockSizes> {
            state: &'a mut Block<Self>,
            blocks: &'a [Block<Self>],
        }

        impl<N: BlockSizes> BlockSizeUser for Closure<'_, N> {
            type BlockSize = N;
        }

        impl<N: BlockSizes> BlockCipherEncClosure for Closure<'_, N> {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                for block in self.blocks {
                    xor(self.state, block);
                    backend.encrypt_block((self.state).into());
                }
            }
        }

        let Self { cipher, state, .. } = self;
        cipher.encrypt_with_backend(Closure { state, blocks })
    }
}

impl<C> Reset for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let mut buf = buffer.pad_with_zeros();

        let cipher = &mut self.cipher;
        let r = &self.r;
        let bs = r.len();
        let mut new_r = Block::<C>::default();
        if pos == bs {
            // phi1
            let (h1, h2) = new_r.split_at_mut(bs - 4);
            h1.copy_from_slice(&r[4..]);
            for i in 0..4 {
                h2[i] = r[i] ^ r[4 + i];
            }
        } else {
            buf[pos] = 0x80;
            // phi2
            let (h1, h2) = new_r.split_at_mut(4);
            for i in 0..4 {
                h1[i] = r[i] ^ r[bs - 4 + i];
            }
            h2.copy_from_slice(&r[..bs - 4]);
        }

        let mut state = self.state.clone();
        xor(&mut state, &buf);
        xor(&mut state, &new_r);
        cipher.encrypt_block_b2b(&state, out);
    }
}

impl<C> AlgorithmName for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltMacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for BeltMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for BeltMacCore<C> where C: BlockCipherEncrypt + Clone + ZeroizeOnDrop {}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
