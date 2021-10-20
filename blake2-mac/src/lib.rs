//! MAC functionality of BLAKE2
//!
//! ## Message Authentication Code (MAC)
//!
//! BLAKE2 can be used as MAC:
//!
//! ```rust
//! use blake2_mac::Blake2bMac512;
//! use blake2_mac::crypto_mac::{Mac, KeyInit, Update};
//!
//! let mut hasher = Blake2bMac512::new_from_slice(b"my key").unwrap();
//! hasher.update(b"hello world");
//!
//! // `result` has type `crypto_mac::Output` which is a thin wrapper around
//! // a byte array and provides a constant time equality check
//! let result = hasher.finalize();
//! // To get underlying array use the `into_bytes` method, but be careful,
//! // since incorrect use of the code value may permit timing attacks which
//! // defeat the security provided by the `crypto_mac::Output`
//! let code_bytes = result.into_bytes();
//!
//! // To verify the message it's recommended to use `verify` method
//! let mut hasher = Blake2bMac512::new_from_slice(b"my key").unwrap();
//! hasher.update(b"hello world");
//! // `verify` return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! hasher.verify(&code_bytes).unwrap();
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use crypto_mac;

use blake2::{
    digest::{
        block_buffer::{DigestBuffer, LazyBlockBuffer},
        core_api::VariableOutputCore,
    },
    Blake2bVarCore, Blake2sVarCore,
};
use core::{fmt, marker::PhantomData};
use crypto_mac::{
    consts::{U32, U64},
    crypto_common::{
        BlockSizeUser, FixedOutput, KeySizeUser, Output, OutputSizeUser, Update, UpdateCore,
    },
    generic_array::{
        typenum::{IsLessOrEqual, LeEq, NonZero, Unsigned},
        ArrayLength,
    },
    InvalidLength, Key, KeyInit, Mac,
};

macro_rules! blake2_mac_impl {
    (
        $name:ident, $hash:ty, $max_size:ty, $doc:expr
    ) => {
        #[derive(Clone)]
        #[doc=$doc]
        pub struct $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            core: $hash,
            buffer: LazyBlockBuffer<<$hash as BlockSizeUser>::BlockSize>,
            _out: PhantomData<OutSize>,
        }

        impl<OutSize> KeySizeUser for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            type KeySize = <$hash as BlockSizeUser>::BlockSize;
        }

        impl<OutSize> KeyInit for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            fn new(key: &Key<Self>) -> Self {
                Self {
                    core: <$hash>::new_with_params(key, &[], key.len(), OutSize::USIZE),
                    buffer: LazyBlockBuffer::new(key),
                    _out: PhantomData,
                }
            }

            fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
                if key.len() > <$hash as BlockSizeUser>::BlockSize::USIZE {
                    return Err(InvalidLength);
                }
                Ok(Self {
                    core: <$hash>::new_with_params(key, &[], key.len(), OutSize::USIZE),
                    buffer: LazyBlockBuffer::new(key),
                    _out: PhantomData,
                })
            }
        }

        impl<OutSize> Update for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            #[inline]
            fn update(&mut self, input: &[u8]) {
                let Self { core, buffer, .. } = self;
                buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
            }
        }

        impl<OutSize> OutputSizeUser for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            type OutputSize = OutSize;
        }

        impl<OutSize> FixedOutput for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            #[inline]
            fn finalize_into(mut self, out: &mut Output<Self>) {
                let Self { core, buffer, .. } = &mut self;
                core.finalize_variable_core(buffer, OutSize::USIZE, |res| out.copy_from_slice(res));
            }
        }

        impl<OutSize> Mac for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
        }

        impl<OutSize> fmt::Debug for $name<OutSize>
        where
            OutSize: ArrayLength<u8> + IsLessOrEqual<$max_size>,
            LeEq<OutSize, $max_size>: NonZero,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{} {{ ... }}", stringify!($name), OutSize::USIZE)
            }
        }
    };
}

blake2_mac_impl!(Blake2bMac, Blake2bVarCore, U64, "Blake2b MAC function");
blake2_mac_impl!(Blake2sMac, Blake2sVarCore, U32, "Blake2s MAC function");

/// BLAKE2b-512 MAC state.
pub type Blake2bMac512 = Blake2bMac<U64>;
/// BLAKE2s-256 MAC state.
pub type Blake2sMac256 = Blake2sMac<U32>;
