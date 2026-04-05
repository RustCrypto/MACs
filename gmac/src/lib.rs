#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use aes::{
    Aes128Enc, Aes192, Aes192Enc, Aes256Enc,
    cipher::{BlockEncrypt, BlockSizeUser, IvSizeUser, KeyInit, KeyIvInit, KeySizeUser},
};
use cipher::consts::{U12, U16};
use core::marker::PhantomData;
pub use digest::{self, Mac};
use digest::{FixedOutput, MacMarker, OutputSizeUser, Update};
use generic_array::GenericArray;
use ghash::{GHash, universal_hash::UniversalHash};

#[cfg(feature = "rand_core")]
use common::rand_core::CryptoRng;

pub trait GmacCipher: BlockEncrypt + BlockSizeUser<BlockSize = U16> + KeyInit {}
impl GmacCipher for Aes128Enc {}
impl GmacCipher for Aes192Enc {}
impl GmacCipher for Aes256Enc {}
pub type Gmac128 = Gmac<Aes128Enc, U12>;
pub type Gmac192 = Gmac<Aes192Enc, U12>;
pub type Gmac256 = Gmac<Aes256Enc, U12>;

#[derive(Debug, Clone)]
pub struct Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    /// Encryption cipher.
    cipher: PhantomData<Aes>,

    /// GHASH authenticator.
    ghash: GHash,

    /// Length of the nonce.
    nonce_size: PhantomData<NonceSize>,

    /// Length of the data processed
    data_size: usize,

    /// Mask for final tag creation
    mask: ghash::Block,

    /// Buffer for unaligned data
    buffer: ghash::Block,

    /// Data available in buffer
    buffer_len: usize,
}

const BLOCK_SIZE: usize = 16;

// TODO: Add creation methods

impl<Aes, NonceSize> Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    #[inline]
    fn update_buffer(&mut self, data: &[u8]) -> usize {
        let data_to_copy = usize::min(BLOCK_SIZE - self.buffer_len, data.len());
        let buffer_end = self.buffer_len + data_to_copy;
        self.buffer.as_mut_slice()[self.buffer_len..buffer_end]
            .copy_from_slice(&data[..data_to_copy]);
        self.buffer_len = buffer_end;
        data_to_copy
    }

    #[inline]
    fn hash_buffer(&mut self) {
        debug_assert_eq!(self.buffer_len, BLOCK_SIZE);
        self.ghash.update(&[self.buffer]);
        self.buffer_len = 0;
    }

    // Mostly stolen from aes-gcm
    #[inline]
    fn init(&mut self, cipher: Aes, nonce: &GenericArray<u8, NonceSize>) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        self.mask = aes::Block::default();
        self.mask.copy_from_slice(&j0);
        cipher.encrypt_block(&mut self.mask);
    }

    #[inline]
    fn internal_build(cipher: Aes, nonce: &GenericArray<u8, NonceSize>) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        let ghash = GHash::new(&ghash_key);

        let mut result = Self {
            cipher: PhantomData,
            ghash,
            nonce_size: PhantomData,
            data_size: 0,
            mask: ghash::Block::default(),
            buffer: ghash::Block::default(),
            buffer_len: 0,
        };
        result.init(cipher, nonce);
        result
    }

    #[cfg(feature = "rand_core")]
    #[inline]
    fn generate_nonce(mut rng: impl CryptoRng) -> GenericArray<u8, NonceSize> {
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        rng.fill_bytes(&mut nonce);
        nonce
    }
}

impl<Aes, NonceSize> OutputSizeUser for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    type OutputSize = U16;
}

impl<Aes, NonceSize> KeySizeUser for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, NonceSize> IvSizeUser for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    type IvSize = NonceSize;
}

impl<Aes, NonceSize> MacMarker for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
}

impl<Aes, NonceSize> KeyIvInit for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    fn new(key: &aes::cipher::Key<Self>, iv: &aes::cipher::Iv<Self>) -> Self {
        let cipher = Aes::new(key);
        Self::internal_build(cipher, iv)
    }
}

impl<Aes, NonceSize> Update for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    fn update(&mut self, data: &[u8]) {
        self.data_size += data.len();
        // First handle any buffered data
        let mut offset = 0;

        if self.buffer_len > 0 {
            offset += self.update_buffer(data);
            if self.buffer_len < BLOCK_SIZE {
                // We don't have enough data for an entire block, so just return
                return;
            }
            self.hash_buffer();
        }
        let data = &data[offset..];
        let tail = data.len() % BLOCK_SIZE;
        let data_end = data.len() - tail;
        let (body, tail) = data.split_at(data_end);
        debug_assert_eq!(body.len() % BLOCK_SIZE, 0);
        self.ghash.update_padded(body);
        if !tail.is_empty() {
            self.update_buffer(tail);
        }
    }
}

impl<Aes, NonceSize> FixedOutput for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let mut ghash = self.ghash;
        // First, process any buffered data
        if self.buffer_len != 0 {
            ghash.update_padded(&self.buffer[..self.buffer_len]);
        }
        let bits_hashed = (self.data_size as u64) * 8;
        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&bits_hashed.to_be_bytes());
        ghash.update(&[block]);
        let tag = ghash.finalize();
        for (r, (a, b)) in out
            .as_mut_slice()
            .iter_mut()
            .zip(tag.as_slice().iter().zip(self.mask.as_slice()))
        {
            *r = *a ^ *b;
        }
    }
}
