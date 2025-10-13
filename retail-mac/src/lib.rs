#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, Key, KeyInit, Mac};

/// Block-level implementation.
pub mod block_api;

use block_api::RetailMacCore;
use cipher::{AlgorithmName, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeySizeUser};
use core::{fmt, ops::Mul};
use digest::{
    InvalidLength,
    array::ArraySize,
    block_api::CoreProxy,
    typenum::{Prod, U2},
};

digest::buffer_fixed!(
    /// Generic Retail MAC instance.
    pub struct RetailMac<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone>(RetailMacCore<C>);
    impl: ResetMacTraits;
);

impl<C> KeySizeUser for RetailMac<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
    <C as BlockSizeUser>::BlockSize: Mul<U2>,
    Prod<<C as BlockSizeUser>::BlockSize, U2>: ArraySize,
{
    type KeySize = Prod<<C as BlockSizeUser>::BlockSize, U2>;
}

impl<C> KeyInit for RetailMac<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + KeyInit,
    <C as BlockSizeUser>::BlockSize: Mul<U2>,
    Prod<<C as BlockSizeUser>::BlockSize, U2>: ArraySize,
{
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: KeyInit::new(key),
            buffer: Default::default(),
        }
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        KeyInit::new_from_slice(key).map(|core| Self {
            core,
            buffer: Default::default(),
        })
    }
}

impl<C> AlgorithmName for RetailMac<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
