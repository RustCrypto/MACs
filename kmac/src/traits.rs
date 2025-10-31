use digest::HashMarker;
use digest::block_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, Eager, ExtendableOutputCore, UpdateCore,
};

const FUNCTION_NAME: &[u8] = b"KMAC";

pub trait CShake {
    fn new_cshake(customization: &[u8]) -> Self;
}

impl CShake for sha3::block_api::CShake128Core {
    fn new_cshake(customization: &[u8]) -> Self {
        Self::new_with_function_name(FUNCTION_NAME, customization)
    }
}

impl CShake for sha3::block_api::CShake256Core {
    fn new_cshake(customization: &[u8]) -> Self {
        Self::new_with_function_name(FUNCTION_NAME, customization)
    }
}

/// Trait implemented by eager hashes which expose their block-level core.
pub trait EagerHash: BlockSizeUser {
    /// Block-level core type of the hash.
    type Core: HashMarker
        + CShake
        + UpdateCore
        + ExtendableOutputCore
        + BlockSizeUser<BlockSize = <Self as BlockSizeUser>::BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone;
}

impl<T> EagerHash for T
where
    T: CoreProxy + BlockSizeUser,
    <T as CoreProxy>::Core: HashMarker
        + CShake
        + UpdateCore
        + ExtendableOutputCore
        + BlockSizeUser<BlockSize = <Self as BlockSizeUser>::BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    type Core = T::Core;
}
