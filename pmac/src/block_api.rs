use cipher::{BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, ParBlocks};
use core::fmt;
use dbl::Dbl;
use digest::{
    MacMarker, Output, OutputSizeUser, Reset,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore, Lazy,
        UpdateCore,
    },
    crypto_common::{InnerInit, InnerUser},
    typenum::Unsigned,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Generic PMAC instance
///
/// `LC_SIZE` regulates size of pre-computed table used in PMAC computation.
/// With `LC_SIZE = 20` and for 128-bit block cipher the table is sufficient
/// for 16*2^20 = 16 MiB of input data. For longer messages the `l` value will
/// be computed on the fly from the last table value, which will be a bit less
/// efficient.
#[derive(Clone)]
pub struct PmacCore<C: PmacCipher, const LC_SIZE: usize = 20> {
    state: PmacState<C, LC_SIZE>,
    cipher: C,
}

#[derive(Clone)]
struct PmacState<C: PmacCipher, const LC_SIZE: usize> {
    counter: usize,
    l_inv: Block<C>,
    l_cache: [Block<C>; LC_SIZE],
    tag: Block<C>,
    offset: Block<C>,
}

impl<C: PmacCipher, const LC_SIZE: usize> PmacState<C, LC_SIZE> {
    #[inline(always)]
    fn next_offset(&mut self) -> &Block<C> {
        let ntz = self.counter.trailing_zeros() as usize;
        self.counter += 1;
        let l = if ntz < LC_SIZE {
            self.l_cache[ntz].clone()
        } else {
            let mut block = self.l_cache[LC_SIZE - 1].clone();
            for _ in LC_SIZE - 1..ntz {
                block = C::dbl(block);
            }
            block
        };
        xor(&mut self.offset, &l);
        &self.offset
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> Drop for PmacState<C, LC_SIZE> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.counter.zeroize();
            self.l_inv.zeroize();
            self.l_cache.iter_mut().for_each(|c| c.zeroize());
            self.tag.zeroize();
            self.offset.zeroize();
        }
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> BlockSizeUser for PmacCore<C, LC_SIZE> {
    type BlockSize = C::BlockSize;
}

impl<C: PmacCipher, const LC_SIZE: usize> OutputSizeUser for PmacCore<C, LC_SIZE> {
    type OutputSize = C::BlockSize;
}

impl<C: PmacCipher, const LC_SIZE: usize> InnerUser for PmacCore<C, LC_SIZE> {
    type Inner = C;
}

impl<C: PmacCipher, const LC_SIZE: usize> MacMarker for PmacCore<C, LC_SIZE> {}

impl<C: PmacCipher, const LC_SIZE: usize> Reset for PmacCore<C, LC_SIZE> {
    #[inline(always)]
    fn reset(&mut self) {
        self.state.tag = Default::default();
        self.state.offset = Default::default();
        self.state.counter = 1;
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> BufferKindUser for PmacCore<C, LC_SIZE> {
    type BufferKind = Lazy;
}

impl<C: PmacCipher + AlgorithmName, const LC_SIZE: usize> AlgorithmName for PmacCore<C, LC_SIZE> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pmac<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> fmt::Debug for PmacCore<C, LC_SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PmacCore { ... }")
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> InnerInit for PmacCore<C, LC_SIZE> {
    #[inline]
    fn inner_init(cipher: C) -> Self {
        let mut l = Default::default();
        cipher.encrypt_block(&mut l);
        let l_inv = C::inv_dbl(l.clone());

        let l_cache = [(); LC_SIZE].map(|_| {
            let next_l = C::dbl(l.clone());
            core::mem::replace(&mut l, next_l)
        });

        let state = PmacState {
            l_cache,
            l_inv,
            tag: Default::default(),
            offset: Default::default(),
            counter: 1,
        };
        Self { cipher, state }
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> UpdateCore for PmacCore<C, LC_SIZE> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        struct Closure<'a, C: PmacCipher, const LC_SIZE: usize> {
            state: &'a mut PmacState<C, LC_SIZE>,
            blocks: &'a [Block<C>],
        }

        impl<C: PmacCipher, const LC_SIZE: usize> BlockSizeUser for Closure<'_, C, LC_SIZE> {
            type BlockSize = C::BlockSize;
        }

        impl<C: PmacCipher, const LC_SIZE: usize> BlockCipherEncClosure for Closure<'_, C, LC_SIZE> {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                let Self { mut blocks, state } = self;
                if B::ParBlocksSize::USIZE > 1 {
                    // TODO: replace with `slice::as_chunks` on stabilization
                    // and migration to const generics
                    let mut iter = blocks.chunks_exact(B::ParBlocksSize::USIZE);
                    for chunk in &mut iter {
                        let mut tmp = ParBlocks::<B>::try_from(chunk).expect("size mismatch");

                        for block in tmp.iter_mut() {
                            xor(block, state.next_offset());
                        }

                        backend.encrypt_par_blocks((&mut tmp).into());

                        for t in tmp.iter() {
                            xor(&mut state.tag, t);
                        }
                    }
                    blocks = iter.remainder();
                }

                for block in blocks {
                    let mut block = block.clone();
                    xor(&mut block, state.next_offset());
                    backend.encrypt_block((&mut block).into());
                    xor(&mut state.tag, &block);
                }
            }
        }

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend(Closure { blocks, state })
    }
}

impl<C: PmacCipher, const LC_SIZE: usize> FixedOutputCore for PmacCore<C, LC_SIZE> {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self {
            cipher,
            state: PmacState { tag, l_inv, .. },
        } = self;
        let pos = buffer.get_pos();
        let buf = buffer.pad_with_zeros();
        if pos == buf.len() {
            xor(tag, &buf);
            xor(tag, l_inv);
        } else {
            tag[pos] ^= 0x80;
            xor(tag, &buf);
        }
        cipher.encrypt_block_b2b(tag, out);
    }
}

#[cfg(feature = "zeroize")]
impl<C: PmacCipher + ZeroizeOnDrop, const LC_SIZE: usize> ZeroizeOnDrop for PmacCore<C, LC_SIZE> {}

#[inline(always)]
fn xor<N: ArraySize>(buf: &mut Array<u8, N>, data: &Array<u8, N>) {
    for i in 0..N::USIZE {
        buf[i] ^= data[i];
    }
}

/// Helper trait implemented for block ciphers supported by PMAC.
///
/// Currently this trait is implemented for all block cipher encryptors
/// with block size equal to 64 and 128 bits.
pub trait PmacCipher: BlockSizeUser + BlockCipherEncrypt + Clone {
    /// Double block. See the [`Dbl`] trait docs for more information.
    fn dbl(block: Block<Self>) -> Block<Self>;
    /// Reverse double block.. See the [`Dbl`] trait docs for more information.
    fn inv_dbl(block: Block<Self>) -> Block<Self>;
}

impl<C> PmacCipher for C
where
    Self: BlockSizeUser + BlockCipherEncrypt + Clone,
    Block<Self>: Dbl,
{
    fn dbl(block: Block<Self>) -> Block<Self> {
        block.dbl()
    }

    fn inv_dbl(block: Block<Self>) -> Block<Self> {
        block.inv_dbl()
    }
}
