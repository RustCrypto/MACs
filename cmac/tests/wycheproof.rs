//! Tests from Project Wycheproof:
//! https://github.com/google/wycheproof
#![no_std]
use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
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

new_trunc_test!(wycheproof_cmac_aes128, "wycheproof-aes128", Cmac<Aes128>);
new_trunc_test!(wycheproof_cmac_aes192, "wycheproof-aes192", Cmac<Aes192>);
new_trunc_test!(wycheproof_cmac_aes256, "wycheproof-aes256", Cmac<Aes256>);
