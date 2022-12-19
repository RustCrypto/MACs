//! [Cipher Block Chaining Message Authentication Code (CBC-MAC)][CBC-MAC]
//! implemented in pure Rust and generic over block cipher.
//!
//! **WARNING!** The algorithm has known weaknesses in case of variable-length
//! messages. See the linked Wikipedia article for more information.
//!
//! # Examples
//!
//! ```
//! use cbc_mac::{CbcMac, Mac};
//! use des::Des;
//! use hex_literal::hex;
//!
//! // CBC-MAC with the DES block cipher is equivalent to DAA
//! type Daa = CbcMac<Des>;
//!
//! // test from FIPS 113
//! let key = hex!("0123456789ABCDEF");
//! let mut mac = Daa::new_from_slice(&key).unwrap();
//! mac.update(b"7654321 Now is the time for ");
//! let correct = hex!("F1D30F6849312CA4");
//! mac.verify_slice(&correct).unwrap();
//! ```
//!
//! [CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Mac};

use cipher::{BlockBackend, BlockCipher, BlockClosure, BlockEncryptMut};
use core::fmt;
use digest::{
    block_buffer::Eager,
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

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic CMAC instance.
pub type CbcMac<C> = CoreWrapper<CbcMacCore<C>>;

/// Generic core CMAC instance, which operates over blocks.
#[derive(Clone)]
pub struct CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    cipher: C,
    state: Block<C>,
}

impl<C> BlockSizeUser for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerUser for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type Inner = C;
}

impl<C> MacMarker for CbcMacCore<C> where C: BlockCipher + BlockEncryptMut + Clone {}

impl<C> InnerInit for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let state = Default::default();
        Self { cipher, state }
    }
}

impl<C> BufferKindUser for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    type BufferKind = Eager;
}

impl<C> UpdateCore for CbcMacCore<C>
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

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend_mut(Ctx { state, blocks })
    }
}

impl<C> Reset for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
    C::BlockSize: IsLess<U256>,
    Le<C::BlockSize, U256>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, cipher } = self;
        let pos = buffer.get_pos();
        if pos != 0 {
            xor(state, buffer.pad_with_zeros());
            cipher.encrypt_block_mut(state);
        }
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CbcMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CbcMacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for CbcMacCore<C>
where
    C: BlockCipher + BlockEncryptMut + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for CbcMacCore<C> where
    C: BlockCipher + BlockEncryptMut + Clone + ZeroizeOnDrop
{
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(buf: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
