//! Generic implementation of [Parallelizable Message Authentication Code (PMAC)][1],
//! otherwise known as OMAC1.
//!
//! # Examples
//! We will use AES-128 block cipher from the [aes](https://docs.rs/aes) crate.
//!
//! To get authentication code:
//!
//! ```rust
//! use aes::Aes128;
//! use pmac::{digest::KeyInit, Pmac, Mac};
//!
//! // Create `Mac` trait implementation, namely PMAC-AES128
//! let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//! mac.update(b"input message");
//!
//! // `result` has type `Output` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.finalize();
//! // To get underlying array use `into_bytes` method, but be careful, since
//! // incorrect use of the tag value may permit timing attacks which defeat
//! // the security provided by the `Output` wrapper
//! let tag_bytes = result.into_bytes();
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use aes::Aes128;
//! # use pmac::{digest::KeyInit, Pmac, Mac};
//! let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//!
//! mac.update(b"input message");
//!
//! # let tag_bytes = mac.clone().finalize().into_bytes();
//! // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
//! mac.verify(&tag_bytes).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/PMAC_(cryptography)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
