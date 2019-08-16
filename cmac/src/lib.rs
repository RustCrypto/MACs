//! Generic implementation of Cipher-based Message Authentication Code (CMAC),
//! otherwise known as OMAC1.
//!
//! # Usage
//! We will use AES-128 block cipher from [aes](https://docs.rs/aes) crate.
//!
//! To get the authentication code:
//!
//! ```rust
//! extern crate cmac;
//! extern crate aes;
//!
//! use aes::Aes128;
//! use cmac::{Cmac, Mac};
//!
//! # fn main() {
//! // Create `Mac` trait implementation, namely CMAC-AES128
//! let mut mac = Cmac::<Aes128>::new_varkey(b"very secret key.").unwrap();
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
//! # extern crate cmac;
//! # extern crate aes;
//! # use aes::Aes128;
//! # use cmac::{Cmac, Mac};
//! # fn main() {
//! let mut mac = Cmac::<Aes128>::new_varkey(b"very secret key.").unwrap();
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

use core::fmt;

type Block<N> = GenericArray<u8, N>;

/// Generic CMAC instance
#[derive(Clone)]
pub struct Cmac<C>
where
    C: BlockCipher + Clone,
    Block<C::BlockSize>: Dbl,
{
    cipher: C,
    key1: Block<C::BlockSize>,
    key2: Block<C::BlockSize>,
    buffer: Block<C::BlockSize>,
    pos: usize,
}

impl<C> Cmac<C>
where
    C: BlockCipher + Clone,
    Block<C::BlockSize>: Dbl,
{
    fn from_cipher(cipher: C) -> Self {
        let mut subkey = GenericArray::default();
        cipher.encrypt_block(&mut subkey);

        let key1 = subkey.dbl();
        let key2 = key1.clone().dbl();

        Cmac {
            cipher,
            key1,
            key2,
            buffer: Default::default(),
            pos: 0,
        }
    }
}

#[inline(always)]
fn xor<L: ArrayLength<u8>>(buf: &mut Block<L>, data: &Block<L>) {
    for i in 0..L::to_usize() {
        buf[i] ^= data[i];
    }
}

impl<C> Mac for Cmac<C>
where
    C: BlockCipher + Clone,
    Block<C::BlockSize>: Dbl,
    C::BlockSize: Clone,
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
        let n = C::BlockSize::to_usize();

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
            let block = unsafe { &*(l.as_ptr() as *const Block<C::BlockSize>) };
            data = r;

            xor(&mut self.buffer, block);
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
        let n = C::BlockSize::to_usize();
        let mut buf = self.buffer.clone();
        if self.pos == n {
            xor(&mut buf, &self.key1);
        } else {
            xor(&mut buf, &self.key2);
            buf[self.pos] ^= 0x80;
        }
        self.cipher.encrypt_block(&mut buf);
        MacResult::new(buf)
    }

    fn reset(&mut self) {
        self.buffer = Default::default();
        self.pos = 0;
    }
}

impl<C> fmt::Debug for Cmac<C>
where
    C: BlockCipher + fmt::Debug + Clone,
    Block<C::BlockSize>: Dbl,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Cmac-{:?}", self.cipher)
    }
}
