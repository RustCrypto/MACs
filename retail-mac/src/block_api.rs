use cipher::{
    BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    InvalidLength, KeySizeUser,
};
use core::{fmt, ops::Mul};
use digest::{
    Key, KeyInit, MacMarker, Output, OutputSizeUser, Reset,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        UpdateCore,
    },
    common::BlockSizes,
    typenum::{Prod, U2},
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic core Retail MAC instance, which operates over blocks.
#[derive(Clone)]
pub struct RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    cipher: C,
    cipher_prime: C,
    state: Block<C>,
}

impl<C> BlockSizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> KeySizeUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
    <C as BlockSizeUser>::BlockSize: Mul<U2>,
    Prod<<C as BlockSizeUser>::BlockSize, U2>: ArraySize,
{
    type KeySize = Prod<<C as BlockSizeUser>::BlockSize, U2>;
}

impl<C> MacMarker for RetailMacCore<C> where C: BlockCipherEncrypt + BlockCipherDecrypt + Clone {}

impl<C> BufferKindUser for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    type BufferKind = Eager;
}

impl<C> KeyInit for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + KeyInit,
    <C as BlockSizeUser>::BlockSize: Mul<U2>,
    Prod<<C as BlockSizeUser>::BlockSize, U2>: ArraySize,
{
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).unwrap()
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let cipher = C::new_from_slice(&key[..key.len() / 2])?;
        let cipher_prime = C::new_from_slice(&key[key.len() / 2..])?;
        Ok(Self {
            cipher,
            cipher_prime,
            state: Block::<Self>::default(),
        })
    }
}

impl<C> UpdateCore for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Closure<'a, N: BlockSizes> {
            state: &'a mut Block<Self>,
            blocks: &'a [Block<Self>],
        }

        impl<N: BlockSizes> BlockSizeUser for Closure<'_, N> {
            type BlockSize = N;
        }

        impl<N: BlockSizes> BlockCipherEncClosure for Closure<'_, N> {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                for block in self.blocks {
                    xor(self.state, block);
                    backend.encrypt_block((self.state).into());
                }
            }
        }

        let Self { cipher, state, .. } = self;
        cipher.encrypt_with_backend(Closure { state, blocks })
    }
}

impl<C> Reset for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self {
            state,
            cipher,
            cipher_prime,
        } = self;
        let pos = buffer.get_pos();
        if pos != 0 {
            xor(state, &buffer.pad_with_zeros());
            cipher.encrypt_block(state);
        }
        cipher_prime.decrypt_block(state);
        cipher.encrypt_block(state);
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetailMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetailMacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<C> Drop for RetailMacCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C> ZeroizeOnDrop for RetailMacCore<C> where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + ZeroizeOnDrop
{
}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
