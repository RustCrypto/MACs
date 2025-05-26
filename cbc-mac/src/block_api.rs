use cipher::{BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt};
use core::fmt;
use digest::{
    MacMarker, Output, OutputSizeUser, Reset,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        UpdateCore,
    },
    crypto_common::{BlockSizes, InnerInit, InnerUser},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic core CMAC instance, which operates over blocks.
#[derive(Clone)]
pub struct CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    cipher: C,
    state: Block<C>,
}

impl<C> BlockSizeUser for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type BlockSize = C::BlockSize;
}

impl<C> OutputSizeUser for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type OutputSize = C::BlockSize;
}

impl<C> InnerUser for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type Inner = C;
}

impl<C> MacMarker for CbcMacCore<C> where C: BlockCipherEncrypt + Clone {}

impl<C> InnerInit for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let state = Default::default();
        Self { cipher, state }
    }
}

impl<C> BufferKindUser for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    type BufferKind = Eager;
}

impl<C> UpdateCore for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
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

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend(Closure { state, blocks })
    }
}

impl<C> Reset for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C> FixedOutputCore for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, cipher } = self;
        let pos = buffer.get_pos();
        if pos != 0 {
            xor(state, &buffer.pad_with_zeros());
            cipher.encrypt_block(state);
        }
        out.copy_from_slice(state);
    }
}

impl<C> AlgorithmName for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CbcMac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CbcMacCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<C> Drop for CbcMacCore<C>
where
    C: BlockCipherEncrypt + Clone,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C> ZeroizeOnDrop for CbcMacCore<C> where C: BlockCipherEncrypt + Clone + ZeroizeOnDrop {}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}
