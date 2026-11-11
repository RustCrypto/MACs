//! `ZeroizeOnDrop` tests.
#![cfg(feature = "zeroize")]

use digest::zeroize::ZeroizeOnDrop;
use hmac::{
    Hmac, HmacReset,
    block_api::{HmacCore, HmacResetCore},
};
use sha2::{Sha256, Sha512};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn zeroize_on_drop() {
    assert_zeroize_on_drop::<HmacCore<Sha256>>();
    assert_zeroize_on_drop::<HmacResetCore<Sha256>>();
    assert_zeroize_on_drop::<Hmac<Sha256>>();
    assert_zeroize_on_drop::<HmacReset<Sha256>>();
    assert_zeroize_on_drop::<Hmac<Sha512>>();
    assert_zeroize_on_drop::<HmacReset<Sha512>>();
}
