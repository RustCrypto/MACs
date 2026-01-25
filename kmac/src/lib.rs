//! [NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encoding;
mod kmac;
mod traits;

use crate::kmac::KmacCore;
use digest::block_api::{Block, BlockSizeUser, Buffer, ExtendableOutputCore, XofReaderCore};
use digest::block_buffer::ReadBuffer;
use digest::consts::{U32, U64, U136, U168};
pub use digest::{self, ExtendableOutput, KeyInit, Mac, XofReader};
use digest::{InvalidLength, OutputSizeUser};
use sha3::block_api::Sha3ReaderCore;
use sha3::{CShake128, CShake256};

/// Manually implement the extra KMAC methods and XOF traits.
macro_rules! impl_kmac {
    ($kmac:ident, $cshake:ident, $reader:ident, $block_size:ident, $output_size:ident) => {
        digest::buffer_fixed!(
            /// KMAC implementation as per Section 4 of [NIST SP 800-185].
            pub struct $kmac(KmacCore<$cshake>);
            impl: MacTraits KeyInit;
        );

        impl OutputSizeUser for KmacCore<$cshake> {
            type OutputSize = $output_size;
        }

        impl $kmac {
            /// Create a new KMAC with the given key and customisation.
            ///
            /// Section 4.2 of [NIST SP 800-185] specifies that KMAC takes both a key (K) and an
            /// optional customisation string (S).
            #[inline]
            pub fn new_customization(key: &[u8], customisation: &[u8]) -> Result<Self, InvalidLength> {
                // TODO: KeyInitWithCustomization trait, following KeyInit as new_with_customization and new_from_slice_with_customization.
                // TODO: review the Result, as this implementation is infallible. Currently matching KeyInit::new_from_slice.
                // FUTURE: support key+customisation initialisation via traits.
                let core = KmacCore::<$cshake>::new_customization(key, customisation);
                let buffer = Buffer::<KmacCore<$cshake>>::default();
                Ok(Self { core, buffer })
            }

            /// Finalize this KMAC into a fixed-length output buffer, as defined in Section 4.3
            /// (Definition) of [NIST SP 800-185].
            ///
            /// This method finalizes the KMAC and *mixes the requested output length into the
            /// KMAC domain separation*. That means the resulting bytes are dependent on the
            /// exact length of `out`. Use this when the output length is part of the MAC/derivation
            /// semantics (for example when the length itself must influence the MAC result).
            ///
            /// This is *not* equivalent to calling `finalize_xof()` and then reading `out.len()`
            /// bytes from the returned reader; the two approaches produce different outputs.
            #[inline]
            pub fn finalize_into(&mut self, out: &mut [u8]) {
                // TODO: review method naming.
                // FUTURE: support custom output sizes via traits.
                let buffer = &mut self.buffer;
                self.core.finalize_core(buffer, out);
            }
        }

        /// Reader for KMAC that implements the XOF interface.
        pub struct $reader {
            core: Sha3ReaderCore<$block_size>,
            buffer: ReadBuffer<<Sha3ReaderCore<$block_size> as BlockSizeUser>::BlockSize>,
        }

        impl BlockSizeUser for $reader {
            type BlockSize = <Sha3ReaderCore<$block_size> as BlockSizeUser>::BlockSize;
        }

        impl XofReaderCore for $reader {
            #[inline(always)]
            fn read_block(&mut self) -> Block<Self> {
                self.core.read_block()
            }
        }

        impl XofReader for $reader {
            #[inline(always)]
            fn read(&mut self, buf: &mut [u8]) -> () {
                let Self { core, buffer } = self;
                buffer.read(buf, |block| {
                    *block = XofReaderCore::read_block(core);
                });
            }
        }

        impl ExtendableOutput for $kmac {
            type Reader = $reader;

            /// Finalize this KMAC to a variable-length (extendable) output stream, as defined in
            /// Section 4.3.1 (KMAC with Arbitrary-Length Output) of [NIST SP 800-185].
            ///
            /// The XOF variant finalizes the sponge state without binding the requested
            /// output length into the KMAC domain separation. The returned reader yields
            /// an effectively infinite stream of bytes; reading the first `N` bytes
            /// from the reader (and truncating) produces the same `N`-byte prefix
            /// regardless of whether more bytes will be read later.
            ///
            /// Use `finalize_xof()` when you need a stream of arbitrary length (e.g. for
            /// KDFs or streaming output). Use `finalize_into()` when the requested output
            /// length must influence the MAC result itself.
            #[inline(always)]
            fn finalize_xof(mut self) -> Self::Reader {
                // FUTURE: support extendable output via a MAC trait?
                let Self { core, buffer } = &mut self;
                let core = <KmacCore<$cshake> as ExtendableOutputCore>::finalize_xof_core(core, buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }
    };
}

impl_kmac!(Kmac128, CShake128, Kmac128Reader, U168, U32);
impl_kmac!(Kmac256, CShake256, Kmac256Reader, U136, U64);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hex_literal::hex;

    fn run_kmac128() -> Kmac128 {
        let mut mac = Kmac128::new_customization(b"my secret key", b"S")
            .expect("Failed to create a KMAC128 instance from key");
        mac.update(b"my message");
        mac
    }

    fn run_kmac256() -> Kmac256 {
        let mut mac = Kmac256::new_customization(b"my secret key", b"S")
            .expect("Failed to create a KMAC256 instance from key");
        mac.update(b"my message");
        mac
    }

    #[test]
    #[rustfmt::skip]
    fn test_kmac128() {
        let out_default = run_kmac128().finalize();
        assert_eq!(out_default.as_bytes().as_slice(), &[248, 117, 251, 104, 105, 74, 192, 171, 41, 119, 90, 145, 137, 1, 243, 168, 28, 139, 94, 23, 113, 176, 36, 194, 10, 9, 40, 209, 193, 167, 181, 254]);

        // confirm finalize_into works the same way
        let mut out_into = [0u8; 32];
        run_kmac128().finalize_into(&mut out_into);
        assert_eq!(out_default.as_bytes().as_slice(), &out_into);

        // confirm finalize_into does not compute subsets
        let mut out_into_subset = [0u8; 16];
        run_kmac128().finalize_into(&mut out_into_subset);
        assert_ne!(&out_into_subset, &out_into[..16]);

        // confirm xof is different
        let mut reader_xof = run_kmac128().finalize_xof();
        let mut out_xof = [0u8; 32];
        reader_xof.read(&mut out_xof);
        assert_ne!(out_xof, out_default.as_bytes().as_slice());
        assert_eq!(&out_xof, &[71, 56, 26, 111, 123, 15, 120, 166, 36, 250, 143, 80, 116, 63, 206, 89, 113, 96, 83, 169, 87, 200, 233, 11, 202, 145, 90, 196, 108, 24, 82, 103]);

        // confirm xof is subset
        let mut reader_xof_subset = run_kmac128().finalize_xof();
        let mut out_xof_subset = [0u8; 16];
        reader_xof_subset.read(&mut out_xof_subset);
        assert_eq!(&out_xof[..16], &out_xof_subset);
    }

    #[test]
    #[rustfmt::skip]
    fn test_kmac256() {
        let out_default = run_kmac256().finalize();
        assert_eq!(out_default.as_bytes().as_slice(), &[158, 175, 254, 101, 124, 16, 93, 198, 176, 54, 249, 78, 167, 112, 206, 159, 229, 55, 225, 168, 71, 228, 28, 222, 195, 148, 255, 241, 196, 172, 37, 60, 135, 67, 155, 134, 43, 61, 215, 243, 128, 55, 227, 169, 175, 22, 14, 132, 174, 63, 69, 60, 50, 41, 88, 148, 11, 41, 9, 90, 0, 87, 143, 131]);

        // confirm finalize_into works the same way
        let mut out_into = [0u8; 64];
        run_kmac256().finalize_into(&mut out_into);
        assert_eq!(out_default.as_bytes().as_slice(), &out_into);

        // confirm finalize_into does not compute subsets
        let mut out_into_subset = [0u8; 32];
        run_kmac256().finalize_into(&mut out_into_subset);
        assert_ne!(&out_into_subset, &out_into[..32]);

        // confirm xof is different
        let mut reader_xof = run_kmac256().finalize_xof();
        let mut out_xof = [0u8; 64];
        reader_xof.read(&mut out_xof);
        assert_ne!(out_xof, out_default.as_bytes().as_slice());
        assert_eq!(&out_xof, &[37, 85, 107, 43, 116, 204, 145, 99, 161, 150, 174, 110, 206, 240, 129, 44, 64, 135, 52, 83, 20, 250, 101, 166, 99, 189, 129, 61, 204, 210, 197, 150, 17, 43, 99, 218, 159, 87, 85, 155, 240, 197, 115, 97, 209, 145, 228, 236, 86, 104, 143, 194, 191, 69, 226, 206, 173, 224, 226, 25, 10, 13, 195, 252]);

        // confirm xof is subset
        let mut reader_xof_subset = run_kmac256().finalize_xof();
        let mut out_xof_subset = [0u8; 32];
        reader_xof_subset.read(&mut out_xof_subset);
        assert_eq!(&out_xof[..32], &out_xof_subset);
    }

    #[test]
    fn test_readme_example_verify() {
        let mut mac = Kmac128::new_from_slice(b"key material").unwrap();
        mac.update(b"input message");
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        let expected = hex!(
            "
            c39a8f614f8821443599440df5402787
            0f67e4c47919061584f14a616f3efcf5
        "
        );
        assert_eq!(
            code_bytes[..],
            expected[..],
            "Expected hex output is {}",
            hex::encode(&code_bytes)
        );

        let mut mac = Kmac128::new_from_slice(b"key material").unwrap();
        mac.update(b"input message");
        mac.verify_slice(&expected).unwrap();
    }

    #[test]
    fn test_readme_example_into() {
        let mut mac = Kmac256::new_customization(b"key material", b"customization").unwrap();
        mac.update(b"input message");
        let mut output = [0u8; 32];
        mac.finalize_into(&mut output);

        let expected = hex!(
            "
            85fb77da3a35e4c4b0057c3151e6cc54
            ee401ffe65ec2f0239f439be8896f7b6
        "
        );
        assert_eq!(
            output[..],
            expected[..],
            "Expected hex output is {}",
            hex::encode(&output)
        );
    }

    #[test]
    fn test_readme_example_xof() {
        let mut mac = Kmac256::new_customization(b"key material", b"customization").unwrap();
        mac.update(b"input message");
        let mut reader = mac.finalize_xof();

        let mut output = [0u8; 32];
        reader.read(&mut output);

        let expected = hex!(
            "
            b675b75668eab0706ab05650f34fa1b6
            24051a9a42b5e42cfe9970e8f903d45b
        "
        );
        assert_eq!(
            output[..],
            expected[..],
            "Expected hex output is {}",
            hex::encode(&output)
        );
    }
}
