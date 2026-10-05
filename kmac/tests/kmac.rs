//! KMAC and KMACXOF API tests.

use hex_literal::hex;
use kmac::digest::common::AlgorithmName;
use kmac::{ExtendableOutput, KeyInit, Kmac128, Kmac256, Mac, XofReader};

fn run_kmac128() -> Kmac128 {
    let mut mac = Kmac128::new_customization(b"my secret key", b"S");
    mac.update(b"my message");
    mac
}

fn run_kmac256() -> Kmac256 {
    let mut mac = Kmac256::new_customization(b"my secret key", b"S");
    mac.update(b"my message");
    mac
}

#[test]
fn test_kmac128() {
    let out_default = run_kmac128().finalize();
    assert_eq!(
        out_default.as_bytes().as_slice(),
        hex!("f875fb68694ac0ab29775a918901f3a81c8b5e1771b024c20a0928d1c1a7b5fe")
    );

    // confirm finalize_into_buf works the same way
    let mut out_into = [0u8; 32];
    run_kmac128().finalize_into_buf(&mut out_into);
    assert_eq!(out_default.as_bytes().as_slice(), &out_into);

    // confirm finalize_into_buf does not compute subsets
    let mut out_into_subset = [0u8; 16];
    run_kmac128().finalize_into_buf(&mut out_into_subset);
    assert_ne!(&out_into_subset, &out_into[..16]);

    // confirm xof is different
    let mut reader_xof = run_kmac128().finalize_xof();
    let mut out_xof = [0u8; 32];
    reader_xof.read(&mut out_xof);
    assert_ne!(out_xof, out_default.as_bytes().as_slice());
    assert_eq!(
        &out_xof,
        &hex!("47381a6f7b0f78a624fa8f50743fce59716053a957c8e90bca915ac46c185267")
    );

    // confirm xof is subset
    let mut reader_xof_subset = run_kmac128().finalize_xof();
    let mut out_xof_subset = [0u8; 16];
    reader_xof_subset.read(&mut out_xof_subset);
    assert_eq!(&out_xof[..16], &out_xof_subset);
}

#[test]
fn test_kmac256() {
    let out_default = run_kmac256().finalize();
    assert_eq!(
        out_default.as_bytes().as_slice(),
        hex!(
            "9eaffe657c105dc6b036f94ea770ce9fe537e1a847e41cdec394fff1c4ac253c"
            "87439b862b3dd7f38037e3a9af160e84ae3f453c322958940b29095a00578f83"
        )
    );

    // confirm finalize_into_buf works the same way
    let mut out_into = [0u8; 64];
    run_kmac256().finalize_into_buf(&mut out_into);
    assert_eq!(out_default.as_bytes().as_slice(), &out_into);

    // confirm finalize_into_buf does not compute subsets
    let mut out_into_subset = [0u8; 32];
    run_kmac256().finalize_into_buf(&mut out_into_subset);
    assert_ne!(&out_into_subset, &out_into[..32]);

    // confirm xof is different
    let mut reader_xof = run_kmac256().finalize_xof();
    let mut out_xof = [0u8; 64];
    reader_xof.read(&mut out_xof);
    assert_ne!(out_xof, out_default.as_bytes().as_slice());
    assert_eq!(
        &out_xof,
        &hex!(
            "25556b2b74cc9163a196ae6ecef0812c4087345314fa65a663bd813dccd2c596"
            "112b63da9f57559bf0c57361d191e4ec56688fc2bf45e2ceade0e2190a0dc3fc"
        )
    );

    // confirm xof is subset
    let mut reader_xof_subset = run_kmac256().finalize_xof();
    let mut out_xof_subset = [0u8; 32];
    reader_xof_subset.read(&mut out_xof_subset);
    assert_eq!(&out_xof[..32], &out_xof_subset);
}

#[test]
fn test_readme_example_verify() {
    let mut mac = Kmac128::new_from_slice(b"key material").unwrap();
    mac.update(b"input message");
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let expected = hex!(
        "c39a8f614f8821443599440df5402787"
        "0f67e4c47919061584f14a616f3efcf5"
    );
    assert_eq!(code_bytes[..], expected[..]);

    let mut mac = Kmac128::new_from_slice(b"key material").unwrap();
    mac.update(b"input message");
    mac.verify_slice(&expected).unwrap();
}

#[test]
fn test_readme_example_into() {
    let mut mac = Kmac256::new_customization(b"key material", b"customization");
    mac.update(b"input message");
    let mut output = [0u8; 32];
    mac.finalize_into_buf(&mut output);

    let expected = hex!(
        "85fb77da3a35e4c4b0057c3151e6cc54"
        "ee401ffe65ec2f0239f439be8896f7b6"
    );
    assert_eq!(output[..], expected[..]);
}

#[test]
fn test_readme_example_xof() {
    let mut mac = Kmac256::new_customization(b"key material", b"customization");
    mac.update(b"input message");
    let mut reader = mac.finalize_xof();

    let mut output = [0u8; 32];
    reader.read(&mut output);

    let expected = hex!(
        "b675b75668eab0706ab05650f34fa1b6"
        "24051a9a42b5e42cfe9970e8f903d45b"
    );
    assert_eq!(output[..], expected[..]);
}

#[test]
fn test_debug_and_alg_name() {
    struct AlgName<T>(core::marker::PhantomData<T>);
    impl<T: AlgorithmName> core::fmt::Display for AlgName<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            T::write_alg_name(f)
        }
    }

    let mac = Kmac128::new_from_slice(b"my secret key").unwrap();
    assert_eq!(format!("{mac:?}"), "Kmac128 { ... }");
    let mac = Kmac256::new_from_slice(b"my secret key").unwrap();
    assert_eq!(format!("{mac:?}"), "Kmac256 { ... }");

    assert_eq!(
        AlgName::<Kmac128>(core::marker::PhantomData).to_string(),
        "KMAC128"
    );
    assert_eq!(
        AlgName::<Kmac256>(core::marker::PhantomData).to_string(),
        "KMAC256"
    );
}
