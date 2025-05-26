//! [Cipher Block Chaining Message Authentication Code (CBC-MAC)][CBC-MAC]
//! implemented in pure Rust and generic over block cipher.
//!
//! **WARNING!** The algorithm has known weaknesses in case of variable-length
//! messages. See the linked Wikipedia article for more information.
//!
//! # Examples
//!
//! ```
//! use cbc_mac::{digest::KeyInit, CbcMac, Mac};
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
//! [CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, KeyInit, Mac};

mod block_api;

use cipher::{AlgorithmName, BlockCipherEncrypt};
use core::fmt;
use digest::block_api::CoreProxy;

digest::buffer_fixed!(
    /// Generic CBC-MAC instance.
    pub struct CbcMac<C: BlockCipherEncrypt + Clone>(block_api::CbcMacCore<C>);
    impl: ResetMacTraits InnerInit;
);

impl<C> AlgorithmName for CbcMac<C>
where
    C: BlockCipherEncrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
