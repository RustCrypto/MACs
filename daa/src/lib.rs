//! Data Authentication Algorithm (DAA) implemetnation as defined in the FIPS 113.
//!
//! **WARNING!** The algorithm is not considered secure by today's standards.
//! DO NOT USE it if you don't have to be compatible with legacy software!
//!
//! # Examples
//!
//! ```
//! use daa::{Daa, Mac, NewMac};
//!
//! // test from FIPS 113
//! let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
//! let mut mac = Daa::new_varkey(&key).unwrap();
//! mac.update(b"7654321 Now is the time for ");
//! let correct = [0xF1, 0xD3, 0x0F, 0x68, 0x49, 0x31, 0x2C, 0xA4];
//! mac.verify(&correct).unwrap();
//! ```

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop)]

pub use crypto_mac::{self, Mac, NewMac};

use crypto_mac::generic_array::typenum::Unsigned;
use crypto_mac::generic_array::GenericArray;
use crypto_mac::Output;
use des::block_cipher::{BlockCipher, NewBlockCipher};
use des::Des;

use core::fmt;

type Block = GenericArray<u8, <Des as BlockCipher>::BlockSize>;

/// DAA instance
#[derive(Clone)]
pub struct Daa {
    cipher: Des,
    buffer: Block,
    pos: usize,
}

impl NewMac for Daa {
    type KeySize = <Des as NewBlockCipher>::KeySize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = Des::new(key);
        Self {
            cipher,
            buffer: Default::default(),
            pos: 0,
        }
    }
}

impl Mac for Daa {
    type OutputSize = <Des as BlockCipher>::BlockSize;

    #[inline]
    fn update(&mut self, mut data: &[u8]) {
        let n = <Des as BlockCipher>::BlockSize::to_usize();
        let rem = n - self.pos;

        if data.len() >= rem {
            let (l, r) = data.split_at(rem);
            data = r;
            for (a, b) in self.buffer[self.pos..].iter_mut().zip(l) {
                *a ^= *b;
            }
            self.pos = n;
        } else {
            for (a, b) in self.buffer[self.pos..].iter_mut().zip(data) {
                *a ^= *b;
            }
            self.pos += data.len();
            return;
        }

        while data.len() >= n {
            self.cipher.encrypt_block(&mut self.buffer);

            let (l, r) = data.split_at(n);
            data = r;

            for i in 0..n {
                self.buffer[i] ^= l[i];
            }
        }

        if !data.is_empty() {
            self.cipher.encrypt_block(&mut self.buffer);
            for (a, b) in self.buffer.iter_mut().zip(data) {
                *a ^= *b;
            }
            self.pos = data.len();
        }
    }

    #[inline]
    fn finalize(mut self) -> Output<Self> {
        if self.pos != 0 {
            self.cipher.encrypt_block(&mut self.buffer);
        }

        Output::new(self.buffer)
    }

    #[inline]
    fn reset(&mut self) {
        if self.pos != 0 {
            self.pos = 0;
            self.buffer = Default::default();
        }
    }
}

impl fmt::Debug for Daa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Daa")
    }
}
