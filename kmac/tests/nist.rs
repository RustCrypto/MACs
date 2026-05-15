//! KMAC and KMACXOF test vectors, sourced from NIST SP 800-185 in:
//! - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
//! - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf

use hex_literal::hex;
use kmac::{ExtendableOutput, Kmac128, Kmac256, Mac, XofReader};

struct NistVector {
    key: &'static [u8],
    data: &'static [u8],
    customization: &'static [u8],
    output: &'static [u8],
}

// These same key and data fields are used throughout the test vectors.
const KEY: [u8; 32] = hex!(
    "404142434445464748494A4B4C4D4E4F"
    "505152535455565758595A5B5C5D5E5F"
);
const DATA_SHORT: [u8; 4] = hex!("00010203");
const DATA_LONG: [u8; 200] = hex!(
    "000102030405060708090A0B0C0D0E0F"
    "101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F"
    "303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F"
    "505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F"
    "707172737475767778797A7B7C7D7E7F"
    "808182838485868788898A8B8C8D8E8F"
    "909192939495969798999A9B9C9D9E9F"
    "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
    "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
    "C0C1C2C3C4C5C6C7"
);

#[test]
fn test_kmac128() {
    let vectors: &[NistVector] = &[
        // KMAC Sample #1
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: &[],
            output: &hex!(
                "E5780B0D3EA6F7D3A429C5706AA43A00"
                "FADBD7D49628839E3187243F456EE14E"
            ),
        },
        // KMAC Sample #2
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: b"My Tagged Application",
            output: &hex!(
                "3B1FBA963CD8B0B59E8C1A6D71888B71"
                "43651AF8BA0A7070C0979E2811324AA5"
            ),
        },
        // KMAC Sample #3
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: b"My Tagged Application",
            output: &hex!(
                "1F5B4E6CCA02209E0DCB5CA635B89A15"
                "E271ECC760071DFD805FAA38F9729230"
            ),
        },
    ];
    for (i, v) in vectors.iter().enumerate() {
        let mut hash = Kmac128::new_customization(v.key, v.customization).unwrap();
        hash.update(v.data);
        let result = hash.finalize();
        assert_eq!(result.as_bytes().as_slice().len(), v.output.len(), "#{i}");
        assert_eq!(result.as_bytes().as_slice(), v.output, "#{i}");
    }
}

#[test]
fn test_kmacxof128() {
    let vectors: &[NistVector] = &[
        // KMACXOF Sample #1
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: &[],
            output: &hex!(
                "CD83740BBD92CCC8CF032B1481A0F446"
                "0E7CA9DD12B08A0C4031178BACD6EC35"
            ),
        },
        // KMACXOF Sample #2
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: b"My Tagged Application",
            output: &hex!(
                "31A44527B4ED9F5C6101D11DE6D26F06"
                "20AA5C341DEF41299657FE9DF1A3B16C"),
        },
        // KMACXOF Sample #3
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: b"My Tagged Application",
            output: &hex!(
                "47026C7CD793084AA0283C253EF65849"
                "0C0DB61438B8326FE9BDDF281B83AE0F"),
        },
    ];

    for (i, v) in vectors.iter().enumerate() {
        let mut hash = Kmac128::new_customization(v.key, v.customization).unwrap();
        hash.update(v.data);
        let mut reader = hash.finalize_xof();
        let mut result = [0u8; 32];
        reader.read(&mut result);
        assert_eq!(result.as_slice().len(), v.output.len(), "#{i}");
        assert_eq!(result.as_slice(), v.output, "#{i}");
    }
}

#[test]
fn test_kmac256() {
    let vectors: &[NistVector] = &[
        // KMAC Sample #4
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: b"My Tagged Application",
            output: &hex!(
                "20C570C31346F703C9AC36C61C03CB64"
                "C3970D0CFC787E9B79599D273A68D2F7"
                "F69D4CC3DE9D104A351689F27CF6F595"
                "1F0103F33F4F24871024D9C27773A8DD"
            ),
        },
        // KMAC Sample #5
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: &[],
            output: &hex!(
                "75358CF39E41494E949707927CEE0AF2"
                "0A3FF553904C86B08F21CC414BCFD691"
                "589D27CF5E15369CBBFF8B9A4C2EB178"
                "00855D0235FF635DA82533EC6B759B69"
            ),
        },
        // KMAC Sample #6
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: b"My Tagged Application",
            output: &hex!(
                "B58618F71F92E1D56C1B8C55DDD7CD18"
                "8B97B4CA4D99831EB2699A837DA2E4D9"
                "70FBACFDE50033AEA585F1A2708510C3"
                "2D07880801BD182898FE476876FC8965"
            ),
        },
    ];
    for (i, v) in vectors.iter().enumerate() {
        let mut hash = Kmac256::new_customization(v.key, v.customization).unwrap();
        hash.update(v.data);
        let result = hash.finalize();
        assert_eq!(result.as_bytes().as_slice().len(), v.output.len(), "#{i}");
        assert_eq!(result.as_bytes().as_slice(), v.output, "#{i}");
    }
}

#[test]
fn test_kmacxof256() {
    let vectors: &[NistVector] = &[
        // KMACXOF Sample #4
        NistVector {
            key: &KEY,
            data: &DATA_SHORT,
            customization: b"My Tagged Application",
            output: &hex!(
                "1755133F1534752AAD0748F2C706FB5C"
                "784512CAB835CD15676B16C0C6647FA9"
                "6FAA7AF634A0BF8FF6DF39374FA00FAD"
                "9A39E322A7C92065A64EB1FB0801EB2B"
            ),
        },
        // KMACXOF Sample #5
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: &[],
            output: &hex!(
                "FF7B171F1E8A2B24683EED37830EE797"
                "538BA8DC563F6DA1E667391A75EDC02C"
                "A633079F81CE12A25F45615EC8997203"
                "1D18337331D24CEB8F8CA8E6A19FD98B"
            ),
        },
        // KMACXOF Sample #6
        NistVector {
            key: &KEY,
            data: &DATA_LONG,
            customization: b"My Tagged Application",
            output: &hex!(
                "D5BE731C954ED7732846BB59DBE3A8E3"
                "0F83E77A4BFF4459F2F1C2B4ECEBB8CE"
                "67BA01C62E8AB8578D2D499BD1BB2767"
                "68781190020A306A97DE281DCC30305D"
            ),
        },
    ];

    for (i, v) in vectors.iter().enumerate() {
        let mut hash = Kmac256::new_customization(v.key, v.customization).unwrap();
        hash.update(v.data);
        let mut reader = hash.finalize_xof();
        let mut result = [0u8; 64];
        reader.read(&mut result);
        assert_eq!(result.as_slice().len(), v.output.len(), "#{i}");
        assert_eq!(result.as_slice(), v.output, "#{i}");
    }
}
