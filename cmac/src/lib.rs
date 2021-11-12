//! Generic implementation of [Cipher-based Message Authentication Code (CMAC)][1],
//! otherwise known as OMAC1.
//!
//! # Usage
//! We will use AES-128 block cipher from [aes](https://docs.rs/aes) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! use aes::Aes128;
//! use cmac::{Cmac, Mac};
//! use hex_literal::hex;
//!
//! // Create `Mac` trait implementation, namely CMAC-AES128
//! let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//! mac.update(b"input message");
//!
//! // `result` has type `CtOutput` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.finalize();
//! // To get underlying array use the `into_bytes` method, but be careful,
//! // since incorrect use of the tag value may permit timing attacks which
//! // defeat the security provided by the `CtOutput` wrapper
//! let tag_bytes = result.into_bytes();
//! assert_eq!(tag_bytes[..], hex!("4508cc6ab5e8aea8eb80f135d717d544")[..]);
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # use aes::Aes128;
//! # use cmac::{Cmac, Mac};
//! # use hex_literal::hex;
//! let mut mac = Cmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
//!
//! mac.update(b"input message");
//!
//! let tag_bytes = hex!("4508cc6ab5e8aea8eb80f135d717d544").into();
//! // `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
//! mac.verify(&tag_bytes).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/One-key_MAC

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use digest;
pub use digest::Mac;

use cipher::{BlockEncryptMut, BlockCipher, Block};

use digest::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    crypto_common::{InnerInit, InnerUser, BlockSizeUser},
    core_api::{UpdateCore, FixedOutputCore, BufferUser, CoreWrapper},
    block_buffer::LazyBlockBuffer,
    Output, Reset, OutputSizeUser, MacMarker,
};
use dbl::Dbl;

/// CMAC type which operates over slices.
pub type Cmac<C> = CoreWrapper<CmacCore<C>>;

/// Core CMAC type which operates over blocks.
#[derive(Clone)]
pub struct CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    cipher: C,
    key1: Block<C>,
    key2: Block<C>,
    state: Block<C>,
}

impl<C> MacMarker for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{ }

impl<C> InnerUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type Inner = C;
}

impl<C> BlockSizeUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerInit for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    fn inner_init(mut cipher: C) -> Self {
        let mut subkey = GenericArray::default();
        cipher.encrypt_block_mut(&mut subkey);

        let key1 = subkey.dbl();
        let key2 = key1.clone().dbl();
        let state = GenericArray::default();

        Self { cipher, key1, key2, state }
    }
}

impl<C> UpdateCore for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            xor(&mut self.state, block);
            self.cipher.encrypt_block_mut(&mut self.state);
        }
    }
}

impl<C> BufferUser for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    type Buffer = LazyBlockBuffer<C::BlockSize>;
}

impl<C> FixedOutputCore for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut LazyBlockBuffer<Self::BlockSize>,
        out: &mut Output<Self>,
    ) {
        let pos = buffer.get_pos();
        let mut res = buffer.pad_zeros();
        if pos == C::BlockSize::USIZE {
            xor(&mut res, &self.key1);
        } else {
            res[pos] ^= 0x80;
            xor(&mut res, &self.key2);
        }
        xor(&mut self.state, res);
        self.cipher.encrypt_block_b2b_mut(&self.state, out);
    }
}

impl<C> Reset for CmacCore<C>
where
    C: BlockCipher + BlockEncryptMut,
    Block<C>: Dbl,
{
    #[inline]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

// TODO: impl Debug or AlgorithmName

#[inline(always)]
fn xor<N: ArrayLength<u8>>(
    state: &mut GenericArray<u8, N>,
    data: &GenericArray<u8, N>,
) {
    for i in 0..N::USIZE {
        state[i] ^= data[i];
    }
}
