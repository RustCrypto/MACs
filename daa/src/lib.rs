//! Data Authentication Algorithm (DAA) implemetnation as defined in the FIPS 113.
//!
//! **WARNING!** The algorithm is not considered secure by today's standards.
//! DO NOT USE it if you don't have to be compatible with legacy software!
//!
//! # Examples
//!
//! ```
//! use daa::{Daa, Mac};
//! use hex_literal::hex;
//!
//! // test from FIPS 113
//! let key = hex!("0123456789ABCDEF");
//! let mut mac = Daa::new_from_slice(&key).unwrap();
//! mac.update(b"7654321 Now is the time for ");
//! let correct = hex!("F1D30F6849312CA4");
//! mac.verify(&correct.into()).unwrap();
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/daa/0.6.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop)]

pub use digest;
pub use digest::Mac;

use des::cipher::BlockEncryptMut;

use des::Des;
use digest::{
    block_buffer::Eager,
    core_api::{Block, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore},
    crypto_common::{BlockSizeUser, InnerInit, InnerUser},
    generic_array::{ArrayLength, GenericArray},
    MacMarker, Output, OutputSizeUser, Reset,
};

/// DAA type which operates over slices.
pub type Daa = CoreWrapper<DaaCore>;

/// Core DAA type which operates over blocks.
#[derive(Clone)]
pub struct DaaCore {
    cipher: Des,
    state: Block<Des>,
}

impl MacMarker for DaaCore {}

impl InnerUser for DaaCore {
    type Inner = Des;
}

impl BufferKindUser for DaaCore {
    type BufferKind = Eager;
}

impl BlockSizeUser for DaaCore {
    type BlockSize = <Des as BlockSizeUser>::BlockSize;
}

impl OutputSizeUser for DaaCore {
    type OutputSize = <Des as BlockSizeUser>::BlockSize;
}

impl InnerInit for DaaCore {
    fn inner_init(cipher: Des) -> Self {
        Self {
            cipher,
            state: Default::default(),
        }
    }
}

impl UpdateCore for DaaCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            xor(&mut self.state, block);
            self.cipher.encrypt_block_mut(&mut self.state);
        }
    }
}

impl FixedOutputCore for DaaCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let res = buffer.pad_with_zeros();
        if pos != 0 {
            xor(&mut self.state, res);
            self.cipher.encrypt_block_mut(&mut self.state);
        }
        *out = self.state;
    }
}

impl Reset for DaaCore {
    #[inline]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

// TODO: impl Debug or AlgorithmName

#[inline(always)]
fn xor<N: ArrayLength<u8>>(state: &mut GenericArray<u8, N>, data: &GenericArray<u8, N>) {
    for i in 0..N::USIZE {
        state[i] ^= data[i];
    }
}
