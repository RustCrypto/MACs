//! Test vectors.

macro_rules! test {
    ($mod_name:ident, $test_name:expr, $hash:ty $(, $t:ident)?) => {
        mod $mod_name {
            // TODO(tarcieri): update tests to support RustCrypto/traits#1916
            new_mac_test!(hmac, $test_name, hmac::Hmac<$hash> $(, $t)?);
            new_mac_test!(simple_hmac, $test_name, hmac::SimpleHmac<$hash> $(, $t)?);
            new_resettable_mac_test!(
                hmac_reset,
                $test_name,
                hmac::HmacReset<$hash>
                $(, $t)?
            );
            new_resettable_mac_test!(
                simple_reset_hmac,
                $test_name,
                hmac::SimpleHmacReset<$hash>
                $(, $t)?
            );
        }
    };
}

/// Define MAC test (vendored from `digest` crate)
// TODO(tarcieri): update tests to support RustCrypto/traits#1916
macro_rules! new_mac_test {
    ($name:ident, $test_name:expr, $mac:ty $(,)?) => {
        new_mac_test!($name, $test_name, $mac, "");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_left $(,)?) => {
        new_mac_test!($name, $test_name, $mac, "left");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_right $(,)?) => {
        new_mac_test!($name, $test_name, $mac, "right");
    };
    ($name:ident, $test_name:expr, $mac:ty, $trunc:expr $(,)?) => {
        #[test]
        fn $name() {
            use blobby::Blob3Iterator;
            use core::cmp::min;
            use digest::{KeyInit, Mac};

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> Option<&'static str> {
                let mac0 = <$mac as KeyInit>::new_from_slice(key).unwrap();

                let mut mac = mac0.clone();
                mac.update(input);
                let result = mac.finalize().into_bytes();
                let n = tag.len();
                let result_bytes = match $trunc {
                    "left" => &result[..n],
                    "right" => &result[result.len() - n..],
                    _ => &result[..],
                };
                if result_bytes != tag {
                    return Some("whole message");
                }

                // test reading different chunk sizes
                for chunk_size in 1..min(64, input.len()) {
                    let mut mac = mac0.clone();
                    for chunk in input.chunks(chunk_size) {
                        mac.update(chunk);
                    }
                    let res = match $trunc {
                        "left" => mac.verify_truncated_left(tag),
                        "right" => mac.verify_truncated_right(tag),
                        _ => mac.verify_slice(tag),
                    };
                    if res.is_err() {
                        return Some("chunked message");
                    }
                }

                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, input, tag] = row.unwrap();
                if let Some(desc) = run_test(key, input, tag) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         input:\t{:?}\n\
                         tag:\t{:?}\n",
                        i, desc, key, input, tag,
                    );
                }
            }
        }
    };
}

/// Define resettable MAC test (vendored from `digest` crate)
// TODO(tarcieri): update tests to support RustCrypto/traits#1916
macro_rules! new_resettable_mac_test {
    ($name:ident, $test_name:expr, $mac:ty $(,)?) => {
        new_resettable_mac_test!($name, $test_name, $mac, "");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_left $(,)?) => {
        new_resettable_mac_test!($name, $test_name, $mac, "left");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_right $(,)?) => {
        new_resettable_mac_test!($name, $test_name, $mac, "right");
    };
    ($name:ident, $test_name:expr, $mac:ty, $trunc:expr $(,)?) => {
        #[test]
        fn $name() {
            use blobby::Blob3Iterator;
            use core::cmp::min;
            use digest::{KeyInit, Mac};

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> Option<&'static str> {
                let mac0 = <$mac as KeyInit>::new_from_slice(key).unwrap();

                let mut mac = mac0.clone();
                mac.update(input);
                let result = mac.finalize_reset().into_bytes();
                let n = tag.len();
                let result_bytes = match $trunc {
                    "left" => &result[..n],
                    "right" => &result[result.len() - n..],
                    _ => &result[..],
                };
                if result_bytes != tag {
                    return Some("whole message");
                }

                // test if reset worked correctly
                mac.update(input);
                let res = match $trunc {
                    "left" => mac.verify_truncated_left(tag),
                    "right" => mac.verify_truncated_right(tag),
                    _ => mac.verify_slice(tag),
                };
                if res.is_err() {
                    return Some("after reset");
                }

                // test reading different chunk sizes
                for chunk_size in 1..min(64, input.len()) {
                    let mut mac = mac0.clone();
                    for chunk in input.chunks(chunk_size) {
                        mac.update(chunk);
                    }
                    let res = match $trunc {
                        "left" => mac.verify_truncated_left(tag),
                        "right" => mac.verify_truncated_right(tag),
                        _ => mac.verify_slice(tag),
                    };
                    if res.is_err() {
                        return Some("chunked message");
                    }
                }
                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, input, tag] = row.unwrap();
                if let Some(desc) = run_test(key, input, tag) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         input:\t{:?}\n\
                         tag:\t{:?}\n",
                        i, desc, key, input, tag,
                    );
                }
            }
        }
    };
}

// Test vectors from RFC 2104, plus wiki test
test!(md5_rfc2104, "md5", md5::Md5);

// Test vectors from RFC 4231
test!(sha224_rfc4231, "sha224", sha2::Sha224);
test!(sha256_rfc4231, "sha256", sha2::Sha256);
test!(sha384_rfc4231, "sha384", sha2::Sha384);
test!(sha512_rfc4231, "sha512", sha2::Sha512);

// Test vectors from R 50.1.113-2016:
// https://tc26.ru/standard/rs/Р%2050.1.113-2016.pdf
test!(streebog256, "streebog256", streebog::Streebog256);
test!(streebog512, "streebog512", streebog::Streebog512);

// Tests from Project Wycheproof:
// https://github.com/google/wycheproof
test!(sha1_wycheproof, "wycheproof-sha1", sha1::Sha1, trunc_left);
test!(
    sha256_wycheproof,
    "wycheproof-sha256",
    sha2::Sha256,
    trunc_left
);
test!(
    sha384_wycheproof,
    "wycheproof-sha384",
    sha2::Sha384,
    trunc_left
);
test!(
    sha512_wycheproof,
    "wycheproof-sha512",
    sha2::Sha512,
    trunc_left
);
