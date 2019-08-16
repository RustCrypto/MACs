//! Data Authentication Algorithm (DAA) implemetnation as defined in the FIPS 113.
//!
//! **WARNING!** The algorithm is not considered secure by today's standards.
//! DO NOT USE it if you don't have to be compatible with legacy software!
//!
//! # Examples
//!
//! ```
//! use daa::{Daa, Mac};
//!
//! // test from FIPS 113
//! let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
//! let mut mac = Daa::new_varkey(&key).unwrap();
//! mac.input(b"7654321 Now is the time for ");
//! let correct = [0xF1, 0xD3, 0x0F, 0x68, 0x49, 0x31, 0x2C, 0xA4];
//! mac.verify(&correct).unwrap();
//! ```
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
pub extern crate crypto_mac;
extern crate des;

use crypto_mac::generic_array::typenum::Unsigned;
use crypto_mac::generic_array::GenericArray;
pub use crypto_mac::Mac;
use crypto_mac::MacResult;
use des::block_cipher_trait::BlockCipher;
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

impl Mac for Daa {
    type OutputSize = <Des as BlockCipher>::BlockSize;
    type KeySize = <Des as BlockCipher>::KeySize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = Des::new(key);
        Self {
            cipher,
            buffer: Default::default(),
            pos: 0,
        }
    }

    #[inline]
    fn input(&mut self, mut data: &[u8]) {
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

        if data.len() != 0 {
            self.cipher.encrypt_block(&mut self.buffer);
            for (a, b) in self.buffer.iter_mut().zip(data) {
                *a ^= *b;
            }
            self.pos = data.len();
        }
    }

    #[inline]
    fn result(mut self) -> MacResult<Self::OutputSize> {
        if self.pos != 0 {
            self.cipher.encrypt_block(&mut self.buffer);
        }
        MacResult::new(self.buffer)
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
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Daa")
    }
}
