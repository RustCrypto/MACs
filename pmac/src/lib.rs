//! Generic implementation of Parallelizable Message Authentication Code (PMAC),
//! otherwise known as OMAC1.
//!
//! # Usage
//! We will use AES-128 block cipher from [aes](https://docs.rs/aes) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! extern crate pmac;
//! extern crate aes;
//!
//! use aes::Aes128;
//! use pmac::{Pmac, Mac};
//!
//! # fn main() {
//! // Create `Mac` trait implementation, namely PMAC-AES128
//! let mut mac = Pmac::<Aes128>::new_varkey(b"very secret key.").unwrap();
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
//! # extern crate aes;
//! # use aes::Aes128;
//! # use pmac::{Pmac, Mac};
//! # fn main() {
//! let mut mac = Pmac::<Aes128>::new_varkey(b"very secret key.").unwrap();
//!
//! mac.input(b"input message");
//!
//! # let code_bytes = mac.clone().result().code();
//! // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! mac.verify(&code_bytes).unwrap();
//! # }
//! ```
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_cipher_trait;
pub extern crate crypto_mac;
extern crate dbl;

use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use block_cipher_trait::BlockCipher;
pub use crypto_mac::Mac;
use crypto_mac::{InvalidKeyLength, MacResult};
use dbl::Dbl;

use core::{fmt, slice};

type Block<N> = GenericArray<u8, N>;
type ParBlocks<N, M> = GenericArray<GenericArray<u8, N>, M>;

/// Will use only precomputed table up to 16*2^20 = 16 MB of input data
/// (for 128 bit cipher), after that will dynamically calculate L value if
/// needed. In future it can become parameter of `Pmac`.
const LC_SIZE: usize = 20;

/// Generic PMAC instance
#[derive(Clone)]
pub struct Pmac<C>
where
    C: BlockCipher + Clone,
    C::BlockSize: Clone,
    C::ParBlocks: Clone,
    Block<C::BlockSize>: Dbl,
{
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
where
    C: BlockCipher + Clone,
    C::BlockSize: Clone,
    C::ParBlocks: Clone,
    Block<C::BlockSize>: Dbl,
{
    fn from_cipher(cipher: C) -> Self {
        let mut l0 = Default::default();
        cipher.encrypt_block(&mut l0);

        let mut l_cache: [Block<C::BlockSize>; LC_SIZE] = Default::default();
        l_cache[0] = l0.clone();
        for i in 1..LC_SIZE {
            l_cache[i] = l_cache[i - 1].clone().dbl();
        }

        let l_inv = l0.clone().inv_dbl();

        Self {
            cipher,
            l_inv,
            l_cache,
            buffer: Default::default(),
            tag: Default::default(),
            offset: Default::default(),
            pos: 0,
            counter: 1,
        }
    }

    /// Process full buffer and update tag
    #[inline(always)]
    fn process_buffer(&mut self) {
        let mut offset = self.offset.clone();
        let mut counter = self.counter;
        let mut buf = self.buffer.clone();
        for val in buf.iter_mut() {
            let l = self.get_l(counter);
            xor(&mut offset, &l);
            counter += 1;
            xor(val, &offset);
        }
        self.counter = counter;
        self.offset = offset;

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
                &mut self.buffer as *mut ParBlocks<C::BlockSize, C::ParBlocks> as *mut u8,
                C::BlockSize::to_usize() * C::ParBlocks::to_usize(),
            )
        }
    }

    #[inline(always)]
    fn get_l(&self, counter: usize) -> Block<C::BlockSize> {
        let ntz = counter.trailing_zeros() as usize;
        if ntz < LC_SIZE {
            self.l_cache[ntz].clone()
        } else {
            let mut block = self.l_cache[LC_SIZE - 1].clone();
            for _ in LC_SIZE - 1..ntz {
                block = block.dbl();
            }
            block
        }
    }
}

impl<C> Mac for Pmac<C>
where
    C: BlockCipher + Clone,
    C::BlockSize: Clone,
    C::ParBlocks: Clone,
    Block<C::BlockSize>: Dbl,
{
    type OutputSize = C::BlockSize;
    type KeySize = C::KeySize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::from_cipher(C::new(key))
    }

    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        let cipher = C::new_varkey(key).map_err(|_| InvalidKeyLength)?;
        Ok(Self::from_cipher(cipher))
    }

    #[inline]
    fn input(&mut self, mut data: &[u8]) {
        let n = C::BlockSize::to_usize() * C::ParBlocks::to_usize();

        let p = self.pos;
        let rem = n - p;
        if data.len() >= rem {
            let (l, r) = data.split_at(rem);
            data = r;
            self.as_mut_bytes()[p..].clone_from_slice(l);
        } else {
            self.as_mut_bytes()[p..p + data.len()].clone_from_slice(data);
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

    fn result(self) -> MacResult<Self::OutputSize> {
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
        let n = if is_full {
            (self.pos / bs) - 1
        } else {
            self.pos / bs
        };
        assert!(n < C::ParBlocks::to_usize(), "invalid buffer position");

        let mut offset = self.offset.clone();
        let mut counter = self.counter;
        for i in 0..n {
            let mut buf = self.buffer[i].clone();

            let l = self.get_l(counter);
            xor(&mut offset, &l);
            xor(&mut buf, &offset);
            self.cipher.encrypt_block(&mut buf);

            xor(&mut tag, &buf);
            counter += 1;
        }

        if is_full {
            xor(&mut tag, &self.buffer[n]);
            xor(&mut tag, &self.l_inv);
        } else {
            let mut block = self.buffer[n].clone();
            block[k] = 0x80;
            for v in block[k + 1..].iter_mut() {
                *v = 0;
            }
            xor(&mut tag, &block);
        }

        self.cipher.encrypt_block(&mut tag);
        MacResult::new(tag)
    }

    fn reset(&mut self) {
        self.buffer = Default::default();
        self.tag = Default::default();
        self.offset = Default::default();
        self.pos = 0;
        self.counter = 1;
    }
}

impl<C> fmt::Debug for Pmac<C>
where
    C: BlockCipher + Clone + fmt::Debug,
    C::BlockSize: Clone,
    C::ParBlocks: Clone,
    Block<C::BlockSize>: Dbl,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Pmac-{:?}", self.cipher)
    }
}
