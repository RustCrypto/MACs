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

use block_api::PmacCipher;
use core::fmt;
use digest::block_api::{AlgorithmName, CoreProxy};

digest::buffer_fixed!(
    /// Generic PMAC instance with `LC_SIZE` = 20.
    pub struct Pmac<C: PmacCipher>(block_api::PmacCore<C, 20>);
    impl: ResetMacTraits InnerInit;
);

impl<C: PmacCipher + AlgorithmName> AlgorithmName for Pmac<C> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
