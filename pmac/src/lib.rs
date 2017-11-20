//! Generic implementation of Parallelizable Message Authentication Code (PMAC),
//! otherwise known as OMAC1.
//!
//! # Usage
//! We will use AES-128 block cipher from [aesni](https://docs.rs/aesni) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! extern crate pmac;
//! extern crate aesni;
//!
//! use aesni::Aes128;
//! use pmac::{Pmac, Mac};
//!
//! # fn main() {
//! // Create `Mac` trait implementation, namely PMAC-AES128
//! let mut mac = Pmac::<Aes128>::new(b"very secret key.").unwrap();
//! mac.input(b"input message");
//!
//! // `result` has type `MacResult` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = mac.result();
//! // To get underlying array use `code` method, but be carefull, since
//! // incorrect use of the code value may permit timing attacks which defeat
//! // the security provided by the `MacResult`
//! let code_bytes = result.code();
//! # }
//! ```
//!
//! To verify the message:
//!
//! ```rust
//! # extern crate pmac;
//! # extern crate aesni;
//! # use aesni::Aes128;
//! # use pmac::{Pmac, Mac};
//! # fn main() {
//! let mut mac = Pmac::<Aes128>::new(b"very secret key.").unwrap();
//!
//! mac.input(b"input message");
//!
//! # let mac2 = mac.clone();
//! # let code_bytes = mac2.result().code();
//! // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! mac.verify(&code_bytes).unwrap();
//! # }
//! ```
#![no_std]
extern crate block_cipher_trait;
pub extern crate crypto_mac;

pub use crypto_mac::Mac;
use crypto_mac::{InvalidKeyLength, MacResult};
use block_cipher_trait::{BlockCipher, NewVarKey};
use block_cipher_trait::generic_array::{GenericArray, ArrayLength};
use block_cipher_trait::generic_array::typenum::Unsigned;

use core::slice;

mod double;

pub use double::Doublable;

type Block<N> = GenericArray<u8, N>;
type ParBlocks<N, M> = GenericArray<GenericArray<u8, N>, M>;

// in future it can be parameter of Pmac
const LC_SIZE: usize = 16;

/// Generic CMAC instance
#[derive(Clone)]
pub struct Pmac<C: BlockCipher + NewVarKey> {
    cipher: C,
    l_inv: Block<C::BlockSize>,
    l_cache: [Block<C::BlockSize>; LC_SIZE],
    buffer: ParBlocks<C::BlockSize, C::ParBlocks>,
    tag: Block<C::BlockSize>,
    offset: Block<C::BlockSize>,
    pos: usize,
    counter: usize,
}

#[inline(always)]
fn xor<L: ArrayLength<u8>>(buf: &mut Block<L>, data: &Block<L>) {
    for i in 0..L::to_usize() {
        buf[i] ^= data[i];
    }
}

impl<C> Pmac<C>
    where C: BlockCipher + NewVarKey, Block<C::BlockSize>: Doublable
{
    /// Process full buffer and update tag
    #[inline(always)]
    fn process_buffer(&mut self) {
        // generate values for xoring with buffer
        let t = {
            let mut buf = ParBlocks::<C::BlockSize, C::ParBlocks>::default();
            for val in buf.iter_mut() {
                let l = self.get_l(self.counter);
                xor(&mut self.offset, &l);
                *val = self.offset.clone();
                self.counter += 1;
            }
            buf
        };
        // Create local buffer copy and xor Ls into it
        let mut buf = self.buffer.clone();
        for (a, b) in buf.iter_mut().zip(t.iter()) {
            xor(a, b);
        }
        // encrypt blocks in the buffer
        self.cipher.encrypt_blocks(&mut buf);
        // and xor them into tag
        for val in buf.iter() {
            xor(&mut self.tag, val);
        }
    }

    /// Represent internall buffer as bytes slice (hopefully in future we will
    /// be able to switch `&mut [u8]` to `&mut [u8; BlockSize*ParBlocks]`)
    #[inline(always)]
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                &mut self.buffer
                    as *mut ParBlocks<C::BlockSize, C::ParBlocks>
                    as *mut u8,
                C::BlockSize::to_usize()*C::ParBlocks::to_usize(),
            )
        }
    }

    #[inline(always)]
    fn get_l(&self, counter: usize) -> Block<C::BlockSize> {
        let ntz = counter.trailing_zeros() as usize;
        if ntz < LC_SIZE {
            self.l_cache[ntz].clone()
        } else {
            let mut block = self.l_cache[LC_SIZE-1].clone();
            for _ in LC_SIZE-1..ntz {
                block = block.double();
            }
            block
        }
    }
}

impl <C> Mac for Pmac<C>
    where C: BlockCipher + NewVarKey, Block<C::BlockSize>: Doublable
{
    type OutputSize = C::BlockSize;

    fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        let cipher = C::new(key).map_err(|_| InvalidKeyLength)?;

        let mut l0 = Default::default();
        cipher.encrypt_block(&mut l0);

        let mut l_cache: [Block<C::BlockSize>; LC_SIZE] = Default::default();
        l_cache[0] = l0.clone();
        for i in 1..LC_SIZE {
            l_cache[i] = l_cache[i-1].clone().double();
        }

        let l_inv = l0.clone().inv_double();

        Ok(Self {
            cipher, l_inv, l_cache,
            buffer: Default::default(), tag: Default::default(),
            offset: Default::default(),
            pos: 0, counter: 1,
        })
    }

    #[inline]
    fn input(&mut self, mut data: &[u8]) {
        let n = C::BlockSize::to_usize()*C::ParBlocks::to_usize();

        let p = self.pos;
        let rem = n - p;
        if data.len() >= rem {
            let (l, r) = data.split_at(rem);
            data = r;
            self.as_mut_bytes()[p..].clone_from_slice(l);
        } else {
            self.as_mut_bytes()[p..p+data.len()]
                .clone_from_slice(data);
            self.pos += data.len();
            return;
        }

        while data.len() >= n {
            self.process_buffer();

            let (l, r) = data.split_at(n);
            self.as_mut_bytes().clone_from_slice(l);
            data = r;
        }

        self.pos = n;

        if data.len() != 0 {
            self.process_buffer();
            self.as_mut_bytes()[..data.len()].clone_from_slice(data);
            self.pos = data.len();
        }
    }

    fn result(mut self) -> MacResult<Self::OutputSize> {
        let mut tag = self.tag.clone();
        // Special case for empty input
        if self.pos == 0 {
            tag[0] = 0x80;
            self.cipher.encrypt_block(&mut tag);
            return MacResult::new(tag);
        }

        let bs = C::BlockSize::to_usize();
        let k = self.pos % bs;
        let is_full = k == 0;
        // number of full blocks excluding last
        let n = if is_full { (self.pos/bs) - 1 } else { self.pos/bs };
        assert!(n < C::ParBlocks::to_usize(), "invalid buffer positions");

        for i in 0..n {
            let mut buf = self.buffer[i].clone();

            let l = self.get_l(self.counter);
            xor(&mut self.offset, &l);
            xor(&mut buf, &self.offset);
            self.cipher.encrypt_block(&mut buf);

            xor(&mut tag, &buf);
            self.counter += 1;
        }

        if is_full {
            xor(&mut tag, &self.buffer[n]);
            xor(&mut tag, &self.l_inv);
        } else {
            let mut block = self.buffer[n].clone();
            block[k] = 0x80;
            for v in block[k+1..].iter_mut() { *v = 0; }
            xor(&mut tag, &block);
        }

        self.cipher.encrypt_block(&mut tag);

        MacResult::new(tag)
    }
}
