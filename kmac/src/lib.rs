#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod encoding;

use crate::encoding::{left_encode, right_encode};
use core::fmt;
use cshake::{CShake, CShake128Reader, CShake256Reader, CShakeReader};
use digest::common::{AlgorithmName, KeySizeUser};
use digest::consts::{U32, U64, U136, U168};
pub use digest::{self, ExtendableOutput, FixedOutput, KeyInit, Mac, XofReader};
use digest::{InvalidLength, MacMarker, Output, OutputSizeUser, Update};

/// KMAC implementation as per Section 4 of [NIST SP 800-185], generic over rate.
///
/// Rate MUST be either 168 or 136 for KMAC128 and KMAC256 respectively.
///
/// [NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone)]
pub struct Kmac<const RATE: usize> {
    cshake: CShake<RATE>,
}

/// KMAC128: KMAC with 128-bit security strength, as defined in Section 4 of
/// [NIST SP 800-185].
///
/// Produces a 32-byte (256-bit) fixed-length output by default via [`Mac::finalize`].
/// For a custom output length where the length is mixed into the domain separation,
/// use [`Kmac::finalize_into_buf`]. For KMACXOF128 (arbitrary-length XOF output), use
/// [`ExtendableOutput::finalize_xof`].
///
/// # Example
/// ```
/// use kmac::{Kmac128, Mac, KeyInit};
///
/// let mut mac = Kmac128::new_from_slice(b"my secret key").unwrap();
/// mac.update(b"input message");
/// let result = mac.finalize();
/// let tag = result.into_bytes();
/// ```
///
/// [NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
pub type Kmac128 = Kmac<168>;

/// KMAC256: KMAC with 256-bit security strength, as defined in Section 4 of
/// [NIST SP 800-185].
///
/// Produces a 64-byte (512-bit) fixed-length output by default via [`Mac::finalize`].
/// For a custom output length where the length is mixed into the domain separation,
/// use [`Kmac::finalize_into_buf`]. For KMACXOF256 (arbitrary-length XOF output), use
/// [`ExtendableOutput::finalize_xof`].
///
/// # Example
/// ```
/// use kmac::{Kmac256, Mac, KeyInit};
///
/// let mut mac = Kmac256::new_from_slice(b"my secret key").unwrap();
/// mac.update(b"input message");
/// let result = mac.finalize();
/// let tag = result.into_bytes();
/// ```
///
/// [NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
pub type Kmac256 = Kmac<136>;

/// KMACXOF128 reader, returned by calling [`ExtendableOutput::finalize_xof`] on [`Kmac128`].
///
/// Implements [`XofReader`] to produce an arbitrary-length output stream (KMACXOF128).
pub type Kmac128Reader = CShake128Reader;

/// KMACXOF256 reader, returned by calling [`ExtendableOutput::finalize_xof`] on [`Kmac256`].
///
/// Implements [`XofReader`] to produce an arbitrary-length output stream (KMACXOF256).
pub type Kmac256Reader = CShake256Reader;

impl<const RATE: usize> MacMarker for Kmac<RATE> {}

impl OutputSizeUser for Kmac128 {
    type OutputSize = U32;
}

impl OutputSizeUser for Kmac256 {
    type OutputSize = U64;
}

impl KeySizeUser for Kmac128 {
    type KeySize = U168;
}

impl KeySizeUser for Kmac256 {
    type KeySize = U136;
}

impl<const RATE: usize> KeyInit for Kmac<RATE>
where
    Self: KeySizeUser,
{
    #[inline]
    fn new(key: &digest::Key<Self>) -> Self {
        Self::new_customization_inner(key.as_slice(), &[])
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self::new_customization_inner(key, &[]))
    }
}

impl<const RATE: usize> Update for Kmac<RATE> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }
}

impl<const RATE: usize> FixedOutput for Kmac<RATE>
where
    Self: OutputSizeUser,
{
    #[inline(always)]
    fn finalize_into(self, out: &mut Output<Self>) {
        self.finalize_fixed_inner(out.as_mut_slice());
    }
}

impl<const RATE: usize> ExtendableOutput for Kmac<RATE> {
    type Reader = CShakeReader<RATE>;

    // Finalize as KMACXOF, a variable-length (extendable) output stream, as defined in
    // Section 4.3.1 (KMAC with Arbitrary-Length Output) of [NIST SP 800-185].
    #[inline(always)]
    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof_inner()
    }
}

impl AlgorithmName for Kmac128 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KMAC128")
    }
}

impl AlgorithmName for Kmac256 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KMAC256")
    }
}

impl fmt::Debug for Kmac128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kmac128 { ... }")
    }
}

impl fmt::Debug for Kmac256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kmac256 { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for Kmac<RATE> {}

impl<const RATE: usize> Kmac<RATE> {
    /// Create a new KMAC with the given key and customisation.
    ///
    /// Section 4.2 of [NIST SP 800-185] specifies that KMAC takes both a key (K) and an
    /// optional customisation string (S).
    #[inline]
    #[must_use]
    pub fn new_customization(key: &[u8], customisation: &[u8]) -> Self {
        Self::new_customization_inner(key, customisation)
    }

    /// Finalize this KMAC into a fixed-length output buffer, as defined in Section 4.3
    /// (Definition) of [NIST SP 800-185].
    ///
    /// This method finalizes the KMAC and *mixes the requested output length into the
    /// KMAC domain separation*. That means the resulting bytes are dependent on the
    /// exact length of `out`. Use this when the output length is part of the MAC/derivation
    /// semantics (for example, when the length itself must influence the MAC result).
    ///
    /// This is *not* equivalent to calling `finalize_xof()` and then reading `out.len()`
    /// bytes from the returned reader; the two approaches produce different outputs.
    ///
    /// # Example
    /// ```
    /// use kmac::{Kmac256, Mac};
    ///
    /// let mut mac = Kmac256::new_customization(b"my key", b"my customization");
    /// mac.update(b"input message");
    /// let mut output = [0u8; 48];
    /// mac.finalize_into_buf(&mut output);
    /// ```
    #[inline]
    pub fn finalize_into_buf(self, out: &mut [u8]) {
        self.finalize_fixed_inner(out);
    }

    #[inline(always)]
    fn new_customization_inner(key: &[u8], customisation: &[u8]) -> Self {
        let mut cshake = CShake::<RATE>::new_with_function_name(b"KMAC", customisation);
        let block_size = RATE;
        let mut encode_buffer = [0u8; 9];

        // bytepad: left_encode(w)
        let le_w = left_encode(block_size as u64, &mut encode_buffer);
        let mut total = le_w.len();
        cshake.update(le_w);

        // encode_string(K): left_encode(8*len(K)) || K
        let le_k = left_encode(8 * key.len() as u64, &mut encode_buffer);
        total += le_k.len();
        cshake.update(le_k);

        total += key.len();
        cshake.update(key);

        // pad to block boundary, pad_len is always less than the block size
        let pad_len = (block_size - (total % block_size)) % block_size;
        cshake.update(&[0u8; 168][..pad_len]);

        Self { cshake }
    }

    /// Finalizes the KMAC for any output array size (fixed-length output).
    #[inline(always)]
    fn finalize_fixed_inner(mut self, out: &mut [u8]) {
        // right_encode(L), where L = output length in bits
        let mut encode_buffer = [0u8; 9];
        let re = right_encode(8 * out.len() as u64, &mut encode_buffer);
        self.cshake.update(re);

        let mut reader = self.cshake.finalize_xof();
        reader.read(out);
    }

    /// Finalizes the KMAC for extendable output (XOF).
    #[inline(always)]
    fn finalize_xof_inner(mut self) -> CShakeReader<RATE> {
        // right_encode(0), as L = 0 for extendable output
        let mut encode_buffer = [0u8; 9];
        let re = right_encode(0, &mut encode_buffer);
        self.cshake.update(re);

        self.cshake.finalize_xof()
    }
}
