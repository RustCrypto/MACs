//! Generic implementation of Cipher-based Message Authentication Code (CMAC).

#![no_std]
extern crate block_cipher_trait;
pub extern crate crypto_mac;

pub use crypto_mac::Mac;
use crypto_mac::{InvalidKeyLength, MacResult};
use block_cipher_trait::{BlockCipher, NewVarKey};
use block_cipher_trait::generic_array::{GenericArray, ArrayLength};
use block_cipher_trait::generic_array::typenum::{U8, U16, U32, Unsigned};

use core::mem;

type Block<N> = GenericArray<u8, N>;

struct Cmac<C: BlockCipher + NewVarKey> {
    cipher: C,
    key1: Block<C::BlockSize>,
    key2: Block<C::BlockSize>,
    buffer: Block<C::BlockSize>,
    pos: usize,
}

#[inline(always)]
fn xor<L: ArrayLength<u8>>(buf: &mut Block<L>, data: &Block<L>) {
    for i in 0..L::to_usize() {
        buf[i] ^= data[i];
    }
}

#[inline(always)]
fn dbl_64(input: &mut Block<U8>) {
}

#[inline(always)]
fn dbl_128(input: &mut Block<U16>) {
}

#[inline(always)]
fn dbl_256(input: &mut Block<U32>) {
}

#[inline(always)]
fn dbl<L: ArrayLength<u8>>(input: &mut Block<L>) {
    match L::to_usize() {
        8 => dbl_64(unsafe { mem::transmute(input) }),
        16 => dbl_128(unsafe { mem::transmute(input) }),
        32 => dbl_256(unsafe { mem::transmute(input) }),
        _ => unimplemented!(),
    }
}

impl <C: BlockCipher + NewVarKey> Mac for Cmac<C> {
    type OutputSize = C::BlockSize;

    #[inline]
    fn new(key: &[u8]) -> Result<Cmac<C>, InvalidKeyLength> {
        let cipher = C::new(key).map_err(|_| InvalidKeyLength)?;

        let mut subkey = GenericArray::default();
        cipher.encrypt_block(&mut subkey);

        dbl(&mut subkey);
        let key1 = subkey.clone();
        dbl(&mut subkey);
        let key2 = subkey;

        Ok(Cmac {
            cipher, key1, key2,
            buffer: GenericArray::default(),
            pos: 0,
        })
    }

    #[inline]
    fn input(&mut self, mut data: &[u8]) {
        let n = C::BlockSize::to_usize();

        if self.pos != 0 {
            let rem = n - self.pos;
            if data.len() >= rem {
                let (l, r) = data.split_at(rem);
                data = r;
                for (a, b) in self.buffer[self.pos..].iter_mut().zip(l) {
                    *a ^= *b;
                }
                self.cipher.encrypt_block(&mut self.buffer);
            } else {
                for (a, b) in self.buffer[self.pos..].iter_mut().zip(data) {
                    *a ^= *b;
                }
                self.pos += data.len();
                return;
            }
        }

        while data.len() >= n {
            let (l, r) = data.split_at(n);
            let block = unsafe {
                & *(l.as_ptr() as *const Block<C::BlockSize>)
            };
            data = r;

            xor(&mut self.buffer, block);
            self.cipher.encrypt_block(&mut self.buffer);
        }

        for (a, b) in self.buffer.iter_mut().zip(data) {
            *a ^= *b;
        }
        self.pos = data.len();
    }

    #[inline]
    fn result(mut self) -> MacResult<Self::OutputSize> {
        let n = C::BlockSize::to_usize();
        if self.pos == n {
            xor(&mut self.buffer, &self.key1);
        } else {
            xor(&mut self.buffer, &self.key2);
            self.buffer[self.pos] ^= 0x80;
        }

        self.cipher.encrypt_block(&mut self.buffer);
        MacResult::new(self.buffer)
    }
}
