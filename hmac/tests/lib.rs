//! Test vectors from:
//! - md5: RFC 2104, plus wiki test
//! - sha2: RFC 4231

#![no_std]

use crypto_mac::{new_test, new_trunc_test};
use hmac::Hmac;

new_test!(hmac_md5, "md5", Hmac<md5::Md5>);
new_test!(hmac_sha224, "sha224", Hmac<sha2::Sha224>);
new_test!(hmac_sha256, "sha256", Hmac<sha2::Sha256>);
new_test!(hmac_sha384, "sha384", Hmac<sha2::Sha384>);
new_test!(hmac_sha512, "sha512", Hmac<sha2::Sha512>);
// Test vectors from R 50.1.113-2016:
// https://tc26.ru/standard/rs/Р 50.1.113-2016.pdf
new_test!(hmac_streebog256, "streebog256", Hmac<streebog::Streebog256>);
new_test!(hmac_streebog512, "streebog512", Hmac<streebog::Streebog512>);
// Test vectors from Wycheproof; these may include truncated tags.
new_trunc_test!(hmac_sha1_wycheproof, "wycheproof-sha1", Hmac<sha1::Sha1>);
new_trunc_test!(
    hmac_sha256_wycheproof,
    "wycheproof-sha256",
    Hmac<sha2::Sha256>
);
new_trunc_test!(
    hmac_sha384_wycheproof,
    "wycheproof-sha384",
    Hmac<sha2::Sha384>
);
new_trunc_test!(
    hmac_sha512_wycheproof,
    "wycheproof-sha512",
    Hmac<sha2::Sha512>
);
