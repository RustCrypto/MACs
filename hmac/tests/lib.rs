//! Test vectors from:
//! - md5: RFC 2104, plus wiki test
//! - sha2: RFC 4231

#![no_std]

use crypto_mac::new_test;
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

// TODO: use macro from crypto-mac crate
// use crypto_mac::new_trunc_test;

macro_rules! new_trunc_test {
    ($name:ident, $test_name:expr, $mac:ty) => {
        #[test]
        fn $name() {
            use crypto_mac::dev::blobby::Blob3Iterator;
            use crypto_mac::generic_array::typenum::Unsigned;
            use crypto_mac::{Mac, NewMac};

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> Option<&'static str> {
                let mut mac = <$mac as NewMac>::new_from_slice(key).unwrap();
                mac.update(input);
                let result = mac.finalize_reset();
                let mut len = <$mac as Mac>::OutputSize::to_usize();
                if tag.len() < len {
                    len = tag.len();
                }
                if &result.into_bytes()[..len] != tag {
                    return Some("whole message");
                }
                // test if reset worked correctly
                mac.update(input);
                let result = mac.finalize();
                if &result.into_bytes()[..len] != tag {
                    return Some("after reset");
                }

                let mut mac = <$mac as NewMac>::new_from_slice(key).unwrap();
                // test reading byte by byte
                for i in 0..input.len() {
                    mac.update(&input[i..i + 1]);
                }
                let result = mac.finalize();
                if &result.into_bytes()[..len] != tag {
                    return Some("message byte-by-byte");
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
