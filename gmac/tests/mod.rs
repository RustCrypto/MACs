//! Test vectors.

use aes::{
    Aes128Enc, Aes192Enc, Aes256Enc,
    cipher::{KeyIvInit, Unsigned},
};
use cipher::consts::{U1, U128};
use digest::dev::blobby;
use digest::dev::raw_mac_test;
use gmac::*;
use hex_literal::hex;

#[derive(Copy, Clone, Debug)]
struct GmacTestVector {
    pub key: &'static [u8],
    pub iv: &'static [u8],
    pub data: &'static [u8],
    pub tag: &'static [u8],
}

blobby::parse_into_structs!(
    include_bytes!("data/gmac_aes128.blb");
    static GMAC_128_KATS: &[GmacTestVector { key, iv, data, tag}];
);
blobby::parse_into_structs!(
    include_bytes!("data/gmac_aes192.blb");
    static GMAC_192_KATS: &[GmacTestVector { key, iv, data, tag}];
);
blobby::parse_into_structs!(
    include_bytes!("data/gmac_aes256.blb");
    static GMAC_256_KATS: &[GmacTestVector { key, iv, data, tag}];
);

#[test]
fn debugging_kat() {
    let key = hex!("2fb45e5b8f993a2bfebc4b15b533e0b4");
    let iv = hex!("5b05755f984d2b90f94b8027");
    let expected = hex!("c75b7832b2a2d9bd827412b6ef5769db");

    let mut mac = Gmac128::new_from_slices(&key, &iv).unwrap();
    mac.update(&hex!("e85491b2202caf1d7dce03b97e09331c32473941"));
    let actual = mac.finalize();
    assert_eq!(&expected, actual.as_bytes().as_slice());
}

#[test]
fn gmac128_defaults() {
    test_kats::<Gmac128>("gmac128_defaults", GMAC_128_KATS);
}

#[test]
fn gmac128_iv8() {
    test_kats::<Gmac<Aes128Enc, U1>>("gmac128_iv8", GMAC_128_KATS);
}

#[test]
fn gmac128_iv1024() {
    test_kats::<Gmac<Aes128Enc, U128>>("gmac128_iv1024", GMAC_128_KATS);
}

#[test]
fn gmac192_defaults() {
    test_kats::<Gmac192>("gmac192_defaults", GMAC_192_KATS);
}

#[test]
fn gmac192_iv8() {
    test_kats::<Gmac<Aes192Enc, U1>>("gmac192_iv8", GMAC_192_KATS);
}

#[test]
fn gmac192_iv1024() {
    test_kats::<Gmac<Aes192Enc, U128>>("gmac192_iv1024", GMAC_192_KATS);
}

#[test]
fn gmac256_defaults() {
    test_kats::<Gmac256>("gmac256_defaults", GMAC_256_KATS);
}

#[test]
fn gmac256_iv8() {
    test_kats::<Gmac<Aes256Enc, U1>>("gmac256_iv8", GMAC_256_KATS);
}

#[test]
fn gmac256_iv1024() {
    test_kats::<Gmac<Aes256Enc, U128>>("gmac256_iv1024", GMAC_256_KATS);
}

fn test_kats<MAC>(name: &str, kats: &[GmacTestVector])
where
    MAC: Mac + KeyIvInit + Clone,
{
    let mut test_count = 0;
    let mut skip_count = 0;
    for (idx, tv) in kats.iter().enumerate() {
        if MAC::KeySize::to_usize() != tv.key.len() {
            skip_count += 1;
            continue;
        }
        if MAC::IvSize::to_usize() != tv.iv.len() {
            skip_count += 1;
            continue;
        }
        if MAC::OutputSize::to_usize() < tv.tag.len() {
            skip_count += 1;
            continue;
        }
        let mac = MAC::new_from_slices(tv.key, tv.iv).expect("Incorrect key or IV length");

        if MAC::OutputSize::to_usize() == tv.tag.len() {
            if let Err(reason) = raw_mac_test(
                mac.clone(),
                tv.data,
                tv.tag,
                digest::dev::MacTruncSide::None,
            ) {
                panic!(
                    "\n\
                        Failed test {name}#{idx}\n\
                        reason:\t{reason:?}\n\
                        test vector:\t{tv:?}\n"
                )
            }
        }
        if let Err(reason) = raw_mac_test(mac, tv.data, tv.tag, digest::dev::MacTruncSide::Left) {
            panic!(
                "\n\
                        Failed test (truncated) {name}#{idx}\n\
                        reason:\t{reason:?}\n\
                        test vector:\t{tv:?}\n"
            )
        }

        test_count += 1;
    }
    println!(
        "KeySize: {} IVSize: {} Tested: {} Skipped: {}\n",
        MAC::KeySize::to_usize(),
        MAC::IvSize::to_usize(),
        test_count,
        skip_count
    );
}
