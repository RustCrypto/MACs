use digest::{
    Digest, HashMarker,
    block_api::{
        Block, BlockSizeUser, BufferKindUser, CoreProxy, Eager, FixedOutputCore, UpdateCore,
    },
};

pub(crate) const IPAD: u8 = 0x36;
pub(crate) const OPAD: u8 = 0x5C;

pub(crate) fn get_der_key<D: Digest + BlockSizeUser>(key: &[u8]) -> Block<D> {
    let mut der_key = Block::<D>::default();
    // The key that HMAC processes must be the same as the block size of the
    // underlying hash function. If the provided key is smaller than that,
    // we just pad it with zeros. If its larger, we hash it and then pad it
    // with zeros.
    if key.len() <= der_key.len() {
        der_key[..key.len()].copy_from_slice(key);
    } else {
        let hash = D::digest(key);
        // All commonly used hash functions have block size bigger
        // than output hash size, but to be extra rigorous we
        // handle the potential uncommon cases as well.
        // The condition is calculated at compile time, so this
        // branch gets removed from the final binary.
        if hash.len() <= der_key.len() {
            der_key[..hash.len()].copy_from_slice(&hash);
        } else {
            let n = der_key.len();
            der_key.copy_from_slice(&hash[..n]);
        }
    }
    der_key
}

/// Trait implemented by eager hashes which expose their block-level core.
pub trait EagerHash: BlockSizeUser + Digest {
    /// Block-level core type of the hash.
    type Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BlockSizeUser<BlockSize = <Self as BlockSizeUser>::BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone;
}

impl<T> EagerHash for T
where
    T: CoreProxy + BlockSizeUser + Digest,
    <T as CoreProxy>::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BlockSizeUser<BlockSize = <Self as BlockSizeUser>::BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    type Core = T::Core;
}
