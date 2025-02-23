//! [Retail Message Authentication Code (Retail MAC)][Retail MAC]
//! implemented in pure Rust and generic over block cipher.
//!
//! **WARNING!** The algorithm has known weaknesses in case of variable-length
//! messages. See the Wikipedia article for (CBC-MAC)[CBC-MAC] for more information.
//!
//! # Examples
//!
//! ```
//! use retail_mac::{digest::KeyInit, RetailMac, Mac};
//! use des::Des;
//! use hex_literal::hex;
//!
//! type RetailMacDes = RetailMac<Des>;
//!
//! // test from ISO/IEC 9797-1:2011 section B.4
//! // K and K' are concatenated:
//! let key = hex!("0123456789ABCDEFFEDCBA9876543210");
//!
//! let mut mac = RetailMacDes::new_from_slice(&key).unwrap();
//! mac.update(b"Now is the time for all ");
//! let correct = hex!("A1C72E74EA3FA9B6");
//! mac.verify_slice(&correct).unwrap();
//!
//! let mut mac2 = RetailMacDes::new_from_slice(&key).unwrap();
//! mac2.update(b"Now is the time for it");
//! let correct2 = hex!("2E2B1428CC78254F");
//! mac2.verify_slice(&correct2).unwrap();
//! ```
//!
//! [Retail MAC]: https://en.wikipedia.org/wiki/ISO/IEC_9797-1#MAC_algorithm_3
//! [CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Key, KeyInit, Mac};

use cipher::{
    BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    InvalidLength, KeySizeUser,
};
use core::fmt;
use digest::{
    MacMarker, Output, OutputSizeUser, Reset,
    array::{
        Array, ArraySize,
        typenum::{IsLess, Le, NonZero, U2, U256},
    },
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::BlockSizes,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic Retail MAC instance.
pub type RetailMac<C> = CoreWrapper<RetailMacCore<C>>;

/// Generic core Retail MAC instance, which operates over blocks.
#[derive(Clone)]
pub struct RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    cipher: C,
    cipher_prime: C,
    state: Block<C>,
}

impl<C> BlockSizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> KeySizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
    <C as BlockSizeUser>::BlockSize: core::ops::Mul<U2>,
    <<C as BlockSizeUser>::BlockSize as core::ops::Mul<U2>>::Output: ArraySize,
{
    type KeySize = <<C as BlockSizeUser>::BlockSize as core::ops::Mul<U2>>::Output;
}

impl<C> MacMarker for RetailMacCore<C> where C: BlockCipherEncrypt + BlockCipherDecrypt + Clone {}

impl<C> BufferKindUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type BufferKind = Eager;
}

impl<C> KeyInit for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + KeyInit,
    <C as BlockSizeUser>::BlockSize: core::ops::Mul<U2>,
    <<C as BlockSizeUser>::BlockSize as core::ops::Mul<U2>>::Output: ArraySize,
{
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).unwrap()
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let cipher = C::new_from_slice(&key[..key.len() / 2])?;
        let cipher_prime = C::new_from_slice(&key[key.len() / 2..])?;
        Ok(Self {
            cipher,
            cipher_prime,
            state: Block::<Self>::default(),
        })
    }
}

impl<C> UpdateCore for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
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

impl<C> Reset for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self {
            state,
            cipher,
            cipher_prime,
        } = self;
        let pos = buffer.get_pos();
        if pos != 0 {
            xor(state, &buffer.pad_with_zeros());
            cipher.encrypt_block(state);
        }
        cipher_prime.decrypt_block(state);
        cipher.encrypt_block(state);
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetailMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetailMacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for RetailMacCore<C> where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + ZeroizeOnDrop
{
}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
