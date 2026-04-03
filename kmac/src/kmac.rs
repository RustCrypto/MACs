use crate::encoding::{left_encode, right_encode};
use cshake::CShake;
use digest::block_api::BlockSizeUser;
use digest::common::KeySizeUser;
use digest::typenum::Unsigned;
use digest::{ExtendableOutput, InvalidLength, Key, KeyInit, MacMarker, Update, XofReader};

/// Trait alias for CShake types usable with KMAC.
pub trait CShakeUser: BlockSizeUser + Update + ExtendableOutput + Clone {
    fn new_kmac(customization: &[u8]) -> Self;
}

impl CShakeUser for cshake::CShake128 {
    fn new_kmac(customization: &[u8]) -> Self {
        CShake::new_with_function_name(b"KMAC", customization)
    }
}

impl CShakeUser for cshake::CShake256 {
    fn new_kmac(customization: &[u8]) -> Self {
        CShake::new_with_function_name(b"KMAC", customization)
    }
}

pub struct KmacInner<D: CShakeUser> {
    cshake: D,
}

impl<D: CShakeUser> Clone for KmacInner<D> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            cshake: self.cshake.clone(),
        }
    }
}

impl<D: CShakeUser> MacMarker for KmacInner<D> {}

impl<D: CShakeUser> KeySizeUser for KmacInner<D> {
    type KeySize = D::BlockSize;
}

impl<D: CShakeUser> BlockSizeUser for KmacInner<D> {
    type BlockSize = D::BlockSize;
}

impl<D: CShakeUser> KmacInner<D> {
    #[inline(always)]
    pub fn new_customization(key: &[u8], customisation: &[u8]) -> Self {
        let mut cshake = D::new_kmac(customisation);
        let block_size = D::BlockSize::USIZE;
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

        // pad to block boundary
        let pad_len = (block_size - (total % block_size)) % block_size;
        if pad_len > 0 {
            let zeros = [0u8; 168]; // max block size
            let mut remaining = pad_len;
            while remaining > 0 {
                let chunk = core::cmp::min(remaining, zeros.len());
                cshake.update(&zeros[..chunk]);
                remaining -= chunk;
            }
        }

        Self { cshake }
    }
}

impl<D: CShakeUser> KeyInit for KmacInner<D> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new_customization(key.as_slice(), &[])
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self::new_customization(key, &[]))
    }
}

impl<D: CShakeUser> Update for KmacInner<D> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }
}

impl<D: CShakeUser> KmacInner<D> {
    /// Finalizes the KMAC for any output array size (fixed-length output).
    #[inline(always)]
    pub fn finalize_fixed_inner(mut self, out: &mut [u8]) {
        // right_encode(L), where L = output length in bits
        let mut encode_buffer = [0u8; 9];
        let re = right_encode(8 * out.len() as u64, &mut encode_buffer);
        self.cshake.update(re);

        let mut reader = self.cshake.finalize_xof();
        reader.read(out);
    }

    /// Finalizes the KMAC for extendable output (XOF).
    #[inline(always)]
    pub fn finalize_xof_inner(mut self) -> D::Reader {
        // right_encode(0), as L = 0 for extendable output
        let mut encode_buffer = [0u8; 9];
        let re = right_encode(0, &mut encode_buffer);
        self.cshake.update(re);

        self.cshake.finalize_xof()
    }
}
