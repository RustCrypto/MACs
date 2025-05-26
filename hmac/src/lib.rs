//! Generic implementation of Hash-based Message Authentication Code (HMAC).
//!
//! To use it you will need a cryptographic hash function implementation which
//! implements the [`digest`] crate traits. You can find compatible crates
//! (e.g. [`sha2`]) in the [`RustCrypto/hashes`] repository.
//!
//! This crate provides four HMAC implementations: [`Hmac`], [`HmacReset`],
//! [`SimpleHmac`], and [`SimpleHmacReset`].
//!
//! The first two types are buffered wrappers around block-level
//! [`block_api::HmacCore`] and [`block_api::HmacResetCore`] types respectively.
//! Internally they uses efficient state representation, but work only with
//! hash functions which expose block-level API and consume blocks eagerly
//! (e.g. it will not work with the BLAKE2 family of  hash functions).
//!
//! On the other hand, [`SimpleHmac`] and [`SimpleHmacReset`] are a bit less
//! efficient, but work with all hash functions which implement
//! the [`Digest`][digest::Digest] trait.
//!
//! [`Hmac`] and [`SimpleHmac`] do not support resetting MAC state (i.e. they
//! do not implement the [`Reset`] and [`FixedOutputReset`] traits). Use
//! [`HmacReset`] or [`SimpleHmacReset`] if you want to reuse MAC state.
//!
//! [`Reset`]: digest::Reset
//! [`FixedOutputReset`]: digest::FixedOutputReset
//!
//! # Examples
//! Let us demonstrate how to use HMAC using the SHA-256 hash function.
//!
//! In the following examples [`Hmac`] is interchangeable with [`SimpleHmac`].
//!
//! To get authentication code:
//!
//! ```rust
//! use sha2::Sha256;
//! use hmac::{Hmac, KeyInit, Mac};
//! use hex_literal::hex;
//!
//! // Create alias for HMAC-SHA256
//! type HmacSha256 = Hmac<Sha256>;
//!
//! let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
//!     .expect("HMAC can take key of any size");
//! mac.update(b"input message");
//!
//! // `result` has type `CtOutput` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.finalize();
//! // To get underlying array use `into_bytes`, but be careful, since
//! // incorrect use of the code value may permit timing attacks which defeats
//! // the security provided by the `CtOutput`
//! let code_bytes = result.into_bytes();
//! let expected = hex!("
//!     97d2a569059bbcd8ead4444ff99071f4
//!     c01d005bcefe0d3567e1be628e5fdcd9
//! ");
//! assert_eq!(code_bytes[..], expected[..]);
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use sha2::Sha256;
//! # use hmac::{Hmac, KeyInit, Mac};
//! # use hex_literal::hex;
//! # type HmacSha256 = Hmac<Sha256>;
//! let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
//!     .expect("HMAC can take key of any size");
//!
//! mac.update(b"input message");
//!
//! let code_bytes = hex!("
//!     97d2a569059bbcd8ead4444ff99071f4
//!     c01d005bcefe0d3567e1be628e5fdcd9
//! ");
//! // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! mac.verify_slice(&code_bytes[..]).unwrap();
//! ```
//!
//! # Block and input sizes
//! Usually it is assumed that block size is larger than output size. Due to the
//! generic nature of the implementation, this edge case must be handled as well
//! to remove potential panic. This is done by truncating hash output to the hash
//! block size if needed.
//!
//! [`digest`]: https://docs.rs/digest
//! [`sha2`]: https://docs.rs/sha2
//! [`RustCrypto/hashes`]: https://github.com/RustCrypto/hashes

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
mod simple;
mod simple_reset;
mod utils;

pub use simple::SimpleHmac;
pub use simple_reset::SimpleHmacReset;

use block_api::EagerHash;
use core::fmt;
use digest::block_api::{AlgorithmName, CoreProxy};

digest::buffer_fixed!(
    /// Generic HMAC instance.
    pub struct Hmac<D: EagerHash>(block_api::HmacCore<D>);
    impl: MacTraits KeyInit;
);

impl<D: EagerHash + AlgorithmName> AlgorithmName for Hmac<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}

digest::buffer_fixed!(
    /// Generic HMAC instance with reset support.
    pub struct HmacReset<D: EagerHash>(block_api::HmacResetCore<D>);
    impl: ResetMacTraits KeyInit;
);

impl<D: EagerHash + AlgorithmName> AlgorithmName for HmacReset<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as CoreProxy>::Core::write_alg_name(f)
    }
}
