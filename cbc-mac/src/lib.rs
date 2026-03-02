#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, KeyInit, Mac, block_api::SmallBlockSizeUser};

mod block_api;

use cipher::{AlgorithmName, BlockCipherEncrypt};
use core::fmt;
use digest::block_api::CoreProxy;

digest::buffer_fixed!(
    /// Generic CBC-MAC instance.
    #[derive(Clone)]
    pub struct CbcMac<C: BlockCipherEncrypt + SmallBlockSizeUser>(block_api::CbcMacCore<C>);
    impl: BaseFixedTraits MacMarker Reset FixedOutputReset InnerInit;
);

impl<C> AlgorithmName for CbcMac<C>
where
    C: BlockCipherEncrypt + SmallBlockSizeUser + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
