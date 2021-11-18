//! Generic implementation of Hash-based Message Authentication Code (HMAC).
//!
//! To use it you'll need a cryptographic hash function implementation from
//! the RustCrypto project, e.g. the from the [`sha2`](https://docs.rs/sha2/)
//! crate.
//!
//! # Usage
//! Let us demonstrate how to use HMAC using SHA256 as an example.
//!
//! To get the authentication code:
//!
//! ```rust
//! use sha2::Sha256;
//! use hmac::{Hmac, Mac};
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
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use sha2::Sha256;
//! # use hmac::{Hmac, Mac};
//! # type HmacSha256 = Hmac<Sha256>;
//! let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
//!     .expect("HMAC can take key of any size");
//!
//! mac.update(b"input message");
//!
//! # let code_bytes = mac.clone().finalize().into_bytes();
//! // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! mac.verify(&code_bytes).unwrap();
//! ```
//!
//! # Block and input sizes
//! Usually it is assumed that block size is larger than output size. Due to the
//! generic nature of the implementation, this edge case must be handled as well
//! to remove potential panic scenario. This is done by truncating hash output
//! to the hash block size if needed.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/hmac/0.12.0"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use digest;
pub use digest::Mac;

use core::{fmt, slice};
#[cfg(feature = "reset")]
use digest::Reset;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreProxy, CoreWrapper,
        FixedOutputCore, OutputSizeUser, UpdateCore,
    },
    crypto_common::{Key, KeySizeUser},
    Digest, InvalidLength, KeyInit, MacMarker, Output,
};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// Generic HMAC instance.
pub type Hmac<D> = CoreWrapper<HmacCore<D>>;

/// Generic core HMAC instance, which operates over blocks.
pub struct HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    digest: D::Core,
    opad_digest: D::Core,
    #[cfg(feature = "reset")]
    ipad_digest: D::Core,
}

impl<D> Clone for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            opad_digest: self.opad_digest.clone(),
            #[cfg(feature = "reset")]
            ipad_digest: self.ipad_digest.clone(),
        }
    }
}

impl<D> MacMarker for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
}

impl<D> BufferKindUser for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    type BufferKind = Eager;
}

impl<D> KeySizeUser for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    type KeySize = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;
}

impl<D> BlockSizeUser for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    type BlockSize = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;
}

impl<D> OutputSizeUser for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    type OutputSize = <<D as CoreProxy>::Core as OutputSizeUser>::OutputSize;
}

impl<D> KeyInit for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).unwrap()
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut der_key = Block::<Self>::default();
        // The key that HMAC processes must be the same as the block size of the
        // underlying hash function. If the provided key is smaller than that,
        // we just pad it with zeros. If its larger, we hash it and then pad it
        // with zeros.
        if key.len() <= der_key.len() {
            der_key[..key.len()].copy_from_slice(key);
        } else {
            let hash = D::digest(key);
            // All commonly used hash functions have block size bigger
            // than output hash size, but to be extra rigorous we
            // handle the potential uncommon cases as well.
            // The condition is calcualted at compile time, so this
            // branch gets removed in the final binary.
            if hash.len() <= der_key.len() {
                der_key[..hash.len()].copy_from_slice(&hash);
            } else {
                let n = der_key.len();
                der_key.copy_from_slice(&hash[..n]);
            }
        }

        let mut buf = der_key.clone();
        for b in buf.iter_mut() {
            *b ^= IPAD;
        }
        let mut digest = D::Core::default();
        digest.update_blocks(slice::from_ref(&buf));

        for b in buf.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }

        let mut opad_digest = D::Core::default();
        opad_digest.update_blocks(slice::from_ref(&buf));

        Ok(Self {
            #[cfg(feature = "reset")]
            ipad_digest: digest.clone(),
            opad_digest,
            digest,
        })
    }
}

impl<D> UpdateCore for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D> FixedOutputCore for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut hash = Output::<D::Core>::default();
        self.digest.finalize_fixed_core(buffer, &mut hash);
        // finalize_fixed_core should reset the buffer as well, but
        // to be extra safe we reset it explicitly again.
        buffer.reset();
        #[cfg(not(feature = "reset"))]
        let h = &mut self.opad_digest;
        #[cfg(feature = "reset")]
        let mut h = self.opad_digest.clone();
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}

#[cfg(feature = "reset")]
#[cfg_attr(docsrs, doc(cfg(feature = "reset")))]
impl<D> Reset for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.digest = self.ipad_digest.clone();
    }
}

impl<D> AlgorithmName for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: AlgorithmName
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D::Core as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D> fmt::Debug for HmacCore<D>
where
    D: CoreProxy + Digest,
    D::Core: AlgorithmName
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacCore<")?;
        <D::Core as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}
