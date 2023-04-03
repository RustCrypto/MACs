#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod utils;

use belt_block::BeltBlock;
use cipher::{BlockBackend, BlockCipher, BlockClosure, BlockEncryptMut};
use core::fmt;
pub use digest::{self, Mac};
use digest::{
    block_buffer::Lazy,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::{InnerInit, InnerUser},
    generic_array::{
        typenum::{IsLess, Le, NonZero, U256},
        ArrayLength, GenericArray,
    },
    MacMarker, Output, OutputSizeUser, Reset,
};

use crate::utils::{phi1, phi2};
#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic BeltMac instance.
pub type BeltMac<C = BeltBlock> = CoreWrapper<BeltMacCore<C>>;

#[derive(Clone)]
/// Generic core BeltMac instance, which operates over blocks.
pub struct BeltMacCore<C = BeltBlock>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    cipher: C,
    state: Block<C>,
    r: Block<C>,
}

impl<C> BlockSizeUser for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerUser for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type Inner = C;
}

impl<C> MacMarker for BeltMacCore<C> where C: BlockCipher + BlockEncryptMut + Clone {}

impl<C> InnerInit for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    #[inline]
    fn inner_init(mut cipher: C) -> Self {
        let state = Default::default();
        let mut r = Default::default();
        cipher.encrypt_block_mut(&mut r);
        Self { cipher, state, r }
    }
}

impl<C> BufferKindUser for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type BufferKind = Lazy;
}

impl<C> UpdateCore for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Ctx<'a, N: ArrayLength<u8>> {
            state: &'a mut Block<Self>,
            blocks: &'a [Block<Self>],
        }

        impl<'a, N: ArrayLength<u8>> BlockSizeUser for Ctx<'a, N> {
            type BlockSize = N;
        }

        impl<'a, N: ArrayLength<u8>> BlockClosure for Ctx<'a, N> {
            #[inline(always)]
            fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
                for block in self.blocks {
                    xor(self.state, block);
                    backend.proc_block((self.state).into());
                }
            }
        }

        let Self { cipher, state, .. } = self;
        cipher.encrypt_with_backend_mut(Ctx { state, blocks })
    }
}

impl<C> Reset for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, cipher, r } = self;
        let pos = buffer.get_pos();
        let buf = buffer.pad_with_zeros();
        if pos != buf.len() {
            buf[pos] = 0x80;
        }

        let r = if pos == buf.len() {
            phi1::<C>(r)
        } else {
            phi2::<C>(r)
        };

        xor(state, buf);
        xor(state, &r);
        cipher.encrypt_block_mut(state);
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BeltMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
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
    C: BlockCipher + BlockEncryptMut + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for BeltMacCore<C> where
    C: BlockCipher + BlockEncryptMut + Clone + ZeroizeOnDrop
{
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(buf: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
