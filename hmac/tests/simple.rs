#[cfg(not(feature = "reset"))]
use digest::new_mac_test as new_test;
#[cfg(feature = "reset")]
use digest::new_resettable_mac_test as new_test;
use hmac::SimpleHmac;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use streebog::{Streebog256, Streebog512};

// Test vectors from RFC 2104, plus wiki test
new_test!(rfc2104_simple_hmac_md5, "md5", SimpleHmac<md5::Md5>);

// Test vectors from RFC 4231
new_test!(rfc4231_simple_hmac_sha224, "sha224", SimpleHmac<Sha224>);
new_test!(rfc4231_simple_hmac_sha256, "sha256", SimpleHmac<Sha256>);
new_test!(rfc4231_simple_hmac_sha384, "sha384", SimpleHmac<Sha384>);
new_test!(rfc4231_simple_hmac_sha512, "sha512", SimpleHmac<Sha512>);

// Tests from Project Wycheproof:
// https://github.com/google/wycheproof
new_test!(
    wycheproof_simple_hmac_sha1,
    "wycheproof-sha1",
    SimpleHmac<Sha1>,
    trunc_left,
);
new_test!(
    wycheproof_simple_hmac_sha256,
    "wycheproof-sha256",
    SimpleHmac<Sha256>,
    trunc_left,
);
new_test!(
    wycheproof_simple_hmac_sha384,
    "wycheproof-sha384",
    SimpleHmac<Sha384>,
    trunc_left,
);
new_test!(
    wycheproof_simple_hmac_sha512,
    "wycheproof-sha512",
    SimpleHmac<Sha512>,
    trunc_left,
);

// Test vectors from R 50.1.113-2016:
// https://tc26.ru/standard/rs/Р 50.1.113-2016.pdf
new_test!(
    simple_hmac_streebog256,
    "streebog256",
    SimpleHmac<Streebog256>
);
new_test!(
    simple_hmac_streebog512,
    "streebog512",
    SimpleHmac<Streebog512>
);
