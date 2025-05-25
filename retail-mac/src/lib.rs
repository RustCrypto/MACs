//! [Retail Message Authentication Code (Retail MAC)][Retail MAC]
//! implemented in pure Rust and generic over block cipher.
//!
//! **WARNING!** The algorithm has known weaknesses in case of variable-length
//! messages. See the Wikipedia article for [CBC-MAC] for more information.
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
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_code)]
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
    core_api::CoreProxy,
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
