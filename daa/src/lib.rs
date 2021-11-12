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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop)]

pub use digest;
pub use digest::Mac;

use des::cipher::BlockEncryptMut;

use digest::{
    generic_array::{ArrayLength, GenericArray},
    crypto_common::{InnerInit, InnerUser, BlockSizeUser},
    core_api::{UpdateCore, FixedOutputCore, BufferUser, CoreWrapper},
    block_buffer::BlockBuffer,
    Output, Reset, OutputSizeUser, MacMarker,
};
use des::Des;

/// Block type over which DAA operates.
pub type Block = des::cipher::Block<Des>;

/// DAA type which operates over slices.
pub type Daa = CoreWrapper<DaaCore>;

/// Core DAA type which operates over blocks.
#[derive(Clone)]
pub struct DaaCore {
    cipher: Des,
    state: Block,
}

impl MacMarker for DaaCore { }

impl InnerUser for DaaCore {
    type Inner = Des;
}

impl BlockSizeUser for DaaCore {
    type BlockSize = <Des as BlockSizeUser>::BlockSize;
}

impl OutputSizeUser for DaaCore {
    type OutputSize = <Des as BlockSizeUser>::BlockSize;
}

impl InnerInit for DaaCore {
    fn inner_init(cipher: Des) -> Self {
        Self { cipher, state: Default::default() }
    }
}

impl BufferUser for DaaCore {
    type Buffer = BlockBuffer<Self::BlockSize>;
}

impl UpdateCore for DaaCore {
    fn update_blocks(&mut self, blocks: &[Block]) {
        for block in blocks {
            xor(&mut self.state, block);
            self.cipher.encrypt_block_mut(&mut self.state);
        }
    }
}

impl FixedOutputCore for DaaCore {
    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut Output<Self>,
    ) {
        let pos = buffer.get_pos();
        let res = buffer.pad_with_zeros();
        if pos != 0 {
            xor(&mut self.state, &res);
            self.cipher.encrypt_block_mut(&mut self.state);
        }
        *out = self.state.clone();
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
fn xor<N: ArrayLength<u8>>(
    state: &mut GenericArray<u8, N>,
    data: &GenericArray<u8, N>,
) {
    for i in 0..N::USIZE {
        state[i] ^= data[i];
    }
}
