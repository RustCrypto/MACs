//! Field arithmetic backends

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod pclmulqdq;

#[cfg(feature = "insecure-soft")]
mod soft;

use super::clmul::Clmul;
use core::ops::BitXor;
use Block;

#[cfg(not(any(
    all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    ),
    feature = "insecure-soft"
)))]
compile_error!(
    "no backends available! On x86/x86-64 platforms, enable intrinsics with \
     RUSTFLAGS=\"-Ctarget-cpu=sandybridge -Ctarget-feature=+sse2,+sse4.1\" or \
     enable **INSECURE** portable emulation with the `insecure-soft` feature"
);

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) use self::pclmulqdq::M128i;

#[cfg(all(
    not(all(
        target_feature = "pclmulqdq",
        target_feature = "sse2",
        target_feature = "sse4.1",
        any(target_arch = "x86", target_arch = "x86_64")
    )),
    feature = "insecure-soft"
))]
pub(crate) use self::soft::U64x2 as M128i;

/// Trait representing the arithmetic operations we expect on the XMM registers
pub trait Backend:
    BitXor<Output = Self> + Clmul + Copy + From<Block> + Into<Block> + From<u128>
{
    /// Swap the hi and low 64-bit halves of the register
    fn shuffle(self) -> Self;

    /// Shift the contents of the register left by 64-bits
    fn shl64(self) -> Self;

    /// Shift the contents of the register right by 64-bits
    fn shr64(self) -> Self;
}
