#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, KeyInit, Mac};

/// Block-level implementation.
pub mod block_api;

use cipher::BlockCipherEncrypt;

digest::buffer_fixed!(
    /// BeltMac instance generic over block cipher.
    pub struct GenericBeltMac<C: BlockCipherEncrypt + Clone>(block_api::BeltMacCore<C>);
    impl: ResetMacTraits AlgorithmName InnerInit;
);

/// BeltMac instance.
pub type BeltMac = GenericBeltMac<belt_block::BeltBlock>;
