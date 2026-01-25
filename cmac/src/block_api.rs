use cipher::{BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt};
use core::fmt;
use dbl::Dbl;
use digest::{
    MacMarker, Output, OutputSizeUser, Reset,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore, Lazy,
        UpdateCore,
    },
    common::{BlockSizes, InnerInit, InnerUser},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic core CMAC instance, which operates over blocks.
#[derive(Clone)]
pub struct CmacCore<C: CmacCipher> {
    cipher: C,
    state: Block<C>,
}

impl<C: CmacCipher> BlockSizeUser for CmacCore<C> {
    type BlockSize = C::BlockSize;
}

impl<C: CmacCipher> OutputSizeUser for CmacCore<C> {
    type OutputSize = C::BlockSize;
}

impl<C: CmacCipher> InnerUser for CmacCore<C> {
    type Inner = C;
}

impl<C: CmacCipher> MacMarker for CmacCore<C> {}

impl<C: CmacCipher> InnerInit for CmacCore<C> {
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let state = Default::default();
        Self { cipher, state }
    }
}

impl<C: CmacCipher> BufferKindUser for CmacCore<C> {
    type BufferKind = Lazy;
}

impl<C: CmacCipher> UpdateCore for CmacCore<C> {
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

impl<C: CmacCipher> Reset for CmacCore<C> {
    #[inline(always)]
    fn reset(&mut self) {
        self.state = Default::default();
    }
}

impl<C: CmacCipher> FixedOutputCore for CmacCore<C> {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, cipher } = self;
        let pos = buffer.get_pos();
        let buf = buffer.pad_with_zeros();

        let mut subkey = Default::default();
        cipher.encrypt_block(&mut subkey);
        let key1 = C::dbl(subkey);

        xor(state, &buf);
        if pos == buf.len() {
            xor(state, &key1);
        } else {
            state[pos] ^= 0x80;
            let key2 = C::dbl(key1);
            xor(state, &key2);
        }
        cipher.encrypt_block(state);
        out.copy_from_slice(state);
    }
}

impl<C: CmacCipher + AlgorithmName> AlgorithmName for CmacCore<C> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cmac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C: CmacCipher> fmt::Debug for CmacCore<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CmacCore { ... }")
    }
}

impl<C: CmacCipher> Drop for CmacCore<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C: CmacCipher + ZeroizeOnDrop> ZeroizeOnDrop for CmacCore<C> {}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}

/// Helper trait implemented for cipher supported by CMAC
pub trait CmacCipher: BlockSizeUser + BlockCipherEncrypt + Clone {
    /// Double block. See the [`Dbl`] trait docs for more information.
    fn dbl(block: Block<Self>) -> Block<Self>;
}

impl<C> CmacCipher for C
where
    Self: BlockSizeUser + BlockCipherEncrypt + Clone,
    Block<Self>: Dbl,
{
    fn dbl(block: Block<Self>) -> Block<Self> {
        block.dbl()
    }
}
