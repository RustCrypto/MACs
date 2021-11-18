//! Test vectors from:
//! - md5: RFC 2104, plus wiki test
//! - sha2: RFC 4231

#![no_std]

use digest::new_mac_test;
use hmac::Hmac;

new_mac_test!(hmac_md5, "md5", Hmac<md5::Md5Core>);
new_mac_test!(hmac_sha224, "sha224", Hmac<sha2::Sha224Core>);
new_mac_test!(hmac_sha256, "sha256", Hmac<sha2::Sha256Core>);
new_mac_test!(hmac_sha384, "sha384", Hmac<sha2::Sha384Core>);
new_mac_test!(hmac_sha512, "sha512", Hmac<sha2::Sha512Core>);
// Test vectors from R 50.1.113-2016:
// https://tc26.ru/standard/rs/Р 50.1.113-2016.pdf
new_mac_test!(
    hmac_streebog256,
    "streebog256",
    Hmac<streebog::Streebog256Core>
);
new_mac_test!(
    hmac_streebog512,
    "streebog512",
    Hmac<streebog::Streebog512Core>
);
