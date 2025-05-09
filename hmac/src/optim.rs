use super::{IPAD, OPAD, get_der_key};
use core::{fmt, slice};
use digest::{
    HashMarker, InvalidLength, KeyInit, MacMarker, Output,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreProxy, CoreWrapper,
        FixedOutputCore, OutputSizeUser, UpdateCore,
    },
    crypto_common::{Key, KeySizeUser},
};

/// Generic HMAC instance.
pub type Hmac<D> = CoreWrapper<HmacCore<D>>;

/// Trait implemented by eager hashes which expose their block-level core.
pub trait EagerHash {
    /// Block-level core type of the hash.
    type Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone;
}

impl<D, C> EagerHash for D
where
    D: CoreProxy<Core = C>,
    C: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    type Core = C;
}

/// Generic core HMAC instance, which operates over blocks.
pub struct HmacCore<D: EagerHash> {
    digest: D::Core,
    opad_digest: D::Core,
    #[cfg(feature = "reset")]
    ipad_digest: D::Core,
}

impl<D: EagerHash> Clone for HmacCore<D> {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            opad_digest: self.opad_digest.clone(),
            #[cfg(feature = "reset")]
            ipad_digest: self.ipad_digest.clone(),
        }
    }
}

impl<D: EagerHash> MacMarker for HmacCore<D> {}

impl<D: EagerHash> BufferKindUser for HmacCore<D> {
    type BufferKind = Eager;
}

impl<D: EagerHash> KeySizeUser for HmacCore<D> {
    type KeySize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> BlockSizeUser for HmacCore<D> {
    type BlockSize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> OutputSizeUser for HmacCore<D> {
    type OutputSize = <<D as EagerHash>::Core as OutputSizeUser>::OutputSize;
}

impl<D: EagerHash> KeyInit for HmacCore<D> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).unwrap()
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut buf = get_der_key::<CoreWrapper<D::Core>>(key);
        for b in buf.iter_mut() {
            *b ^= IPAD;
        }
        let mut digest = D::Core::default();
        digest.update_blocks(slice::from_ref(&buf));

        for b in buf.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }

        let mut opad_digest = D::Core::default();
        opad_digest.update_blocks(slice::from_ref(&buf));

        Ok(Self {
            #[cfg(feature = "reset")]
            ipad_digest: digest.clone(),
            opad_digest,
            digest,
        })
    }
}

impl<D: EagerHash> UpdateCore for HmacCore<D> {
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D: EagerHash> FixedOutputCore for HmacCore<D> {
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut hash = Output::<D::Core>::default();
        self.digest.finalize_fixed_core(buffer, &mut hash);
        // finalize_fixed_core should reset the buffer as well, but
        // to be extra safe we reset it explicitly again.
        buffer.reset();
        #[cfg(not(feature = "reset"))]
        let h = &mut self.opad_digest;
        #[cfg(feature = "reset")]
        let mut h = self.opad_digest.clone();
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}

#[cfg(feature = "reset")]
#[cfg_attr(docsrs, doc(cfg(feature = "reset")))]
impl<D: EagerHash> digest::Reset for HmacCore<D> {
    #[inline(always)]
    fn reset(&mut self) {
        self.digest = self.ipad_digest.clone();
    }
}

impl<D: EagerHash> AlgorithmName for HmacCore<D>
where
    D::Core: AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D::Core as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D: EagerHash> fmt::Debug for HmacCore<D>
where
    D::Core: AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacCore<")?;
        <D::Core as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}
