use digest::HashMarker;
use digest::block_api::{
    BufferKindUser, CoreProxy, Eager, ExtendableOutputCore, SmallBlockSizeUser, UpdateCore,
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
pub trait EagerHash: SmallBlockSizeUser {
    /// Block-level core type of the hash.
    type Core: HashMarker
        + CShake
        + UpdateCore
        + ExtendableOutputCore
        + SmallBlockSizeUser<_BlockSize = <Self as SmallBlockSizeUser>::_BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone;
}

impl<T> EagerHash for T
where
    T: CoreProxy + SmallBlockSizeUser,
    <T as CoreProxy>::Core: HashMarker
        + CShake
        + UpdateCore
        + ExtendableOutputCore
        + SmallBlockSizeUser<_BlockSize = <T as SmallBlockSizeUser>::_BlockSize>
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
{
    type Core = T::Core;
}
