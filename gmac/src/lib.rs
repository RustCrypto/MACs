#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use aes::cipher::KeyIvInit;
pub use digest::{self, Mac};

use aes::{
    Aes128Enc, Aes192Enc, Aes256Enc,
    cipher::{BlockEncrypt, BlockSizeUser, IvSizeUser, KeyInit, KeySizeUser},
};
use cipher::consts::{U12, U16};
use core::marker::PhantomData;
use digest::{FixedOutput, MacMarker, OutputSizeUser, Update};
use generic_array::GenericArray;
use ghash::{GHash, universal_hash::UniversalHash};

#[cfg(feature = "rand_core")]
use common::rand_core::{TryCryptoRng, TryRng};

/// Marker trait used to identify specific ciphers which may be used with GMAC.
pub trait GmacCipher: BlockEncrypt + BlockSizeUser<BlockSize = U16> + KeyInit {}
impl GmacCipher for Aes128Enc {}
impl GmacCipher for Aes192Enc {}
impl GmacCipher for Aes256Enc {}

/// GMAC with a 128-bit key and 12 byte nonce.
pub type Gmac128 = Gmac<Aes128Enc, U12>;
/// GMAC with a 192-bit key and 12 byte nonce.
pub type Gmac192 = Gmac<Aes192Enc, U12>;
/// GMAC with a 256-bit key and 12 byte nonce.
pub type Gmac256 = Gmac<Aes256Enc, U12>;

/// GMAC: Generic over an underlying AES implementation and nonce size.
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

impl<Aes, NonceSize> Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    /// Fills the internal buffered block and returns the number of bytes copied from `data`
    #[inline]
    fn update_buffer(&mut self, data: &[u8]) -> usize {
        let data_to_copy = usize::min(Aes::block_size() - self.buffer_len, data.len());
        let buffer_end = self.buffer_len + data_to_copy;
        self.buffer.as_mut_slice()[self.buffer_len..buffer_end]
            .copy_from_slice(&data[..data_to_copy]);
        self.buffer_len = buffer_end;
        data_to_copy
    }

    /// Hash the buffered block. Panics (in debug) if an entire block has not been buffered.
    #[inline]
    fn hash_buffer(&mut self) {
        debug_assert_eq!(self.buffer_len, Aes::block_size());
        self.ghash.update(&[self.buffer]);
        self.buffer_len = 0;
    }

    /// Calculates and sets the mask value used for finalizing the tag value.
    // Mostly stolen from aes-gcm
    #[inline]
    fn init_mask(&mut self, cipher: Aes, nonce: &GenericArray<u8, NonceSize>) {
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

    /// Generate a random nonce for use with GMAC.
    ///
    /// GMAC accepts a parameter to encryption/decryption called a "nonce"
    /// which must be unique every time a MAC is generated and never repeated for the same key.
    /// The nonce is often prepended to the tag. The nonce used to produce a given tag must be
    /// passed to the verification MAC calculation.
    ///
    /// Nonces don’t necessarily have to be random, but it is one strategy which is implemented by this function.
    ///
    /// # ⚠️Security Warning
    ///
    /// GMAC fails catastrophically if the nonce is ever repeated.
    ///
    /// Using random nonces runs the risk of repeating them. The best case for GMAC is with a 12 byte nonce.
    /// With a 12-byte (96-bit) nonce, you can safely generate 2^32 (4,294,967,296) random nonces before the risk
    /// of repeating one becomes too high.
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    pub fn generate_nonce<Rng>(
        mut rng: Rng,
    ) -> Result<GenericArray<u8, NonceSize>, <Rng as TryRng>::Error>
    where
        Rng: TryCryptoRng,
    {
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        rng.try_fill_bytes(&mut nonce)?;
        Ok(nonce)
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
    fn new(key: &aes::cipher::Key<Self>, nonce: &aes::cipher::Iv<Self>) -> Self {
        let cipher = Aes::new(key);

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
        result.init_mask(cipher, nonce);
        result
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
            if self.buffer_len < Aes::block_size() {
                // We don't have enough data for an entire block, so just return
                return;
            }
            self.hash_buffer();
        }
        let data = &data[offset..];
        let tail = data.len() % Aes::block_size();
        let data_end = data.len() - tail;
        let (body, tail) = data.split_at(data_end);
        debug_assert_eq!(body.len() % Aes::block_size(), 0);
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
        let mut ghash = self.ghash.clone();
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

// Optional features
// Zeroize
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
impl<Aes, NonceSize> Drop for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
    fn drop(&mut self) {
        // cipher is PhantomData
        // ghash implements ZeroizeOnDrop
        // nonce_size is PhantomData
        self.data_size.zeroize();
        self.mask.zeroize();
        self.buffer.zeroize();
        // buffer_len is not sensitive
    }
}

#[cfg(feature = "zeroize")]
impl<Aes, NonceSize> ZeroizeOnDrop for Gmac<Aes, NonceSize>
where
    Aes: GmacCipher,
    NonceSize: generic_array::ArrayLength<u8>,
{
}
