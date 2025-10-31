# RustCrypto: KMAC

A rust implementation of [KMAC](https://en.wikipedia.org/wiki/SHA-3#Additional_instances), following the [NIST SP 800-185] specification.

This crate provides implementations for KMAC128, KMAC256, KMACXOF128, and KMACXOF256. KMAC is a PRF and keyed hash function based on the Keccak (SHA-3) sponge construction, designed for message authentication (MAC) and key derivation (KDF).

## NIST security guidance

Security guidance for KMAC is discussed in Section 8.4 of [NIST SP 800-185].

KMAC128 is built from cSHAKE128, giving it a security strength <= 128 bits. The `Kmac128` default MAC tag length is the NIST recommended 32 bytes (256 bits). The input key length must also be at least 16 bytes (128 bits) to achieve the full security strength.

KMAC256 is built from cSHAKE256, giving it a security strength <= 256 bits. The `Kmac256` default MAC tag length is the NIST recommended 64 bytes (512 bits). The input key length must also be at least 32 bytes (256 bits) to achieve the full security strength.

The below table summarises the equivalence with other MAC algorithms, where `K` is the input key, `text` is the input message, `L` is the output tag length, and `S` is an optional customization string.

| Existing MAC Algorithm | KMAC Equivalent              |
|------------------------|------------------------------|
| `AES-KMAC(K, text)`    | `KMAC128(K, text, L=128, S)` |
| `HMAC-SHA256(K, text)` | `KMAC256(K, text, L=256, S)` |
| `HMAC-SHA512(K, text)` | `KMAC256(K, text, L=512, S)` |

## Examples

### Generating a MAC
```rust
use kmac::{Kmac128, Mac, KeyInit};
use hex_literal::hex;

// Use KMAC128 to produce a MAC
let mut kmac = Kmac128::new_from_slice(b"key material").unwrap();
kmac.update(b"input message");

// `result` has type `CtOutput` which is a thin wrapper around array of
// bytes for providing constant time equality check
let result = kmac.finalize();

// To get underlying array use `into_bytes`, but be careful, since
// incorrect use of the code value may permit timing attacks which defeats
// the security provided by the `CtOutput`
let mac_bytes = result.into_bytes();
let expected = hex!("
    c39a8f614f8821443599440df5402787
    0f67e4c47919061584f14a616f3efcf5
");
assert_eq!(mac_bytes[..], expected[..]);
```

### Verifying a MAC
```rust
use kmac::{Kmac128, Mac, KeyInit};
use hex_literal::hex;

let mut kmac = Kmac128::new_from_slice(b"key material").unwrap();
kmac.update(b"input message");

let mac_bytes = hex!("
    c39a8f614f8821443599440df5402787
    0f67e4c47919061584f14a616f3efcf5
");

// `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
kmac.verify_slice(&mac_bytes).unwrap();
```

### Producing a fixed-length output

KMAC can also be used to produce an output of any length, which is particularly useful when KMAC is being used as a [key-derivation function (KDF)](https://en.wikipedia.org/wiki/Key_derivation_function).

This method finalizes the KMAC and mixes the requested output length into the KMAC domain separation. The resulting bytes are dependent on the exact length of `out`. Use this when the output length is part of the MAC/derivation semantics (for example when the length itself must influence the MAC result).

A customisation string can also be provided to further domain-separate different uses of KMAC with the same key when initialising the KMAC instance with `new_customization`.

```rust
use kmac::{Kmac256, Mac};
use hex_literal::hex;

let mut mac = Kmac256::new_customization(b"key material", b"customization").unwrap();
mac.update(b"input message");
let mut output = [0u8; 32];
mac.finalize_into(&mut output);

let expected = hex!("
    85fb77da3a35e4c4b0057c3151e6cc54
    ee401ffe65ec2f0239f439be8896f7b6
");
assert_eq!(output[..], expected[..]);
```

### Producing a variable-length output

Variable length KMAC output uses the `ExtendableOutput` trait. This is useful when the desired output length is not immediately known, and will append data to a buffer until the desired length is reached. 

The XOF variant finalizes the sponge state without binding the requested output length into the KMAC domain separation. The returned reader yields an effectively infinite stream of bytes; reading the first `N` bytes  from the reader (and truncating) produces the same `N`-byte prefix regardless of whether more bytes will be read later.

```rust
use kmac::{Kmac256, Mac, ExtendableOutput, XofReader};
use hex_literal::hex;

let mut kmac = Kmac256::new_customization(b"key material", b"customization").unwrap();
kmac.update(b"input message");
let mut reader = kmac.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);

let expected = hex!("
    b675b75668eab0706ab05650f34fa1b6
    24051a9a42b5e42cfe9970e8f903d45b
");
assert_eq!(output[..], expected[..]);
```

## License

Licensed under either of:
- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)
at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
