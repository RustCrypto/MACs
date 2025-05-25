//! Generic implementation of [Cipher-based Message Authentication Code (CMAC)][1],
//! otherwise known as OMAC1.
//!
//! # Examples
//! We will use AES-128 block cipher from [aes](https://docs.rs/aes) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! use aes::Aes128;
//! use cmac::{digest::KeyInit, Cmac, Mac};
//!
//! // Create `Mac` trait implementation, namely CMAC-AES128
//! let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//! mac.update(b"input message");
//!
//! // `result` has type `Output` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.finalize();
//! // To get underlying array use the `into_bytes` method, but be careful,
//! // since incorrect use of the tag value may permit timing attacks which
//! // defeat the security provided by the `Output` wrapper
//! let tag_bytes = result.into_bytes();
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use aes::Aes128;
//! # use cmac::{digest::KeyInit, Cmac, Mac};
//! let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//!
//! mac.update(b"input message");
//!
//! # let tag_bytes = mac.clone().finalize().into_bytes();
//! // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
//! mac.verify(&tag_bytes).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/One-key_MAC

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

use block_api::CmacCipher;
use core::fmt;
use digest::core_api::{AlgorithmName, CoreProxy};

digest::buffer_fixed!(
    /// Generic CMAC instance.
    pub struct Cmac<C: CmacCipher>(block_api::CmacCore<C>);
    impl: ResetMacTraits InnerInit;
);

impl<C: CmacCipher + AlgorithmName> AlgorithmName for Cmac<C> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
