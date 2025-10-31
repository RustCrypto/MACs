use crate::encoding::{left_encode, right_encode};
use crate::traits::{CShake, EagerHash};
use core::fmt;
use digest::block_api::{
    AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
    FixedOutputCore, UpdateCore, XofReaderCore,
};
use digest::crypto_common::KeySizeUser;
use digest::{InvalidLength, Key, KeyInit, MacMarker, Output, OutputSizeUser};

pub struct KmacCore<D: EagerHash> {
    digest: D::Core,
}

impl<D: EagerHash> Clone for KmacCore<D> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
        }
    }
}

impl<D: EagerHash> MacMarker for KmacCore<D> {}

impl<D: EagerHash> BufferKindUser for KmacCore<D> {
    type BufferKind = Eager;
}

impl<D: EagerHash> KeySizeUser for KmacCore<D> {
    type KeySize = <D::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> BlockSizeUser for KmacCore<D> {
    type BlockSize = <D::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> KmacCore<D> {
    #[inline(always)]
    pub fn new_customization(key: &[u8], customisation: &[u8]) -> Self {
        // digest: bufpad(encode_string(K), bufsize) || X || right_encode(L)
        //   where bufpad(X, w) = left_encode(len(w)) || X || zeros
        //   where encode_string(K) = left_encode(len(K)) || K
        let mut digest = D::Core::new_cshake(customisation);
        let mut buffer = Buffer::<Self>::default();
        let mut encode_buffer = [0u8; 9];

        // bytepad, left_encode(w)
        buffer.digest_blocks(
            left_encode(D::block_size() as u64, &mut encode_buffer),
            |blocks| digest.update_blocks(blocks),
        );

        // encode_string(K), left_encode(len(K)) -- length is in bits
        buffer.digest_blocks(
            left_encode(8 * key.len() as u64, &mut encode_buffer),
            |blocks| digest.update_blocks(blocks),
        );

        // encode_string(K) copy K into blocks
        buffer.digest_blocks(key, |blocks| digest.update_blocks(blocks));

        // bytepad, pad the key to the block size
        digest.update_blocks(&[buffer.pad_with_zeros()]);

        Self { digest }
    }
}

impl<D: EagerHash> KeyInit for KmacCore<D> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new_customization(key.as_slice(), &[])
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self::new_customization(key, &[]))
    }
}

impl<D: EagerHash> UpdateCore for KmacCore<D> {
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D: EagerHash> KmacCore<D> {
    /// Finalizes the KMAC for any output array size.
    #[inline(always)]
    pub fn finalize_core(&mut self, buffer: &mut Buffer<Self>, out: &mut [u8]) {
        // right_encode(L), where L = output length in bits
        buffer.digest_blocks(
            right_encode(8 * out.len() as u64, &mut [0u8; 9]),
            |blocks| self.update_blocks(blocks),
        );

        let mut reader = self.digest.finalize_xof_core(buffer);

        let mut pos = 0;
        while pos < out.len() {
            let block = reader.read_block();
            let to_copy = core::cmp::min(out.len() - pos, block.len());
            out[pos..pos + to_copy].copy_from_slice(&block[..to_copy]);
            pos += to_copy;
        }
    }
}

impl<D: EagerHash> FixedOutputCore for KmacCore<D>
where
    KmacCore<D>: OutputSizeUser,
{
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        self.finalize_core(buffer, out.as_mut_slice());
    }
}

impl<D: EagerHash> ExtendableOutputCore for KmacCore<D> {
    type ReaderCore = <D::Core as ExtendableOutputCore>::ReaderCore;

    #[inline(always)]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        // right_encode(0), as L = 0 for extendable output
        buffer.digest_blocks(right_encode(0, &mut [0u8; 9]), |blocks| {
            self.update_blocks(blocks)
        });
        self.digest.finalize_xof_core(buffer)
    }
}

impl<D: EagerHash + AlgorithmName> AlgorithmName for KmacCore<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kmac<")?;
        <D as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D: EagerHash + fmt::Debug> fmt::Debug for KmacCore<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KmacCore { ... }")
    }
}
