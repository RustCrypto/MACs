# [RustCrypto]: GMAC

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Generic implementation of the [Galois Message Authentication Code (GMAC)][GMAC].

GMAC is defined by NIST [SP 800-38D] as an authentication-only specialization of
GCM (Galois Counter Mode). It is equivalent to GCM encryption with an empty plaintext
and data only provided in the AAD.

**WARNING!** This is a nonce-based MAC and must have a unique nonce for each generation.
This is identical to the issues with nonce-reuse and AES-GCM (which uses GMAC internally).
This also means that it is dangerous to clone an instance of GMAC when generating a MAC.
(It is safe to clone for verification purposes only.)

**WARNING!** GMAC has known weaknesses when used with variable tag lengths associated with the same key. This is identical to the issues with AES-GCM (which uses GMAC internally).
Ensure that only a single tag length is ever used with any given key.

## Examples

We will use AES-128 with a 12 byte IV.
(A good default cipher backed by the `aes` crate.)

To get the authentication code:

```rust
use gmac::{KeyIvInit, Gmac, Gmac128, Mac};
use rand::rngs::SysRng;

// Use the predefined type of `Gmac128`.
# #[cfg(feature = "rand_core" )]
let iv = Gmac128::generate_nonce(SysRng).unwrap();
# #[cfg(not(feature = "rand_core" ))]
# let iv = b"000000000000";
let iv = iv.as_slice();
let mut mac = Gmac128::new_from_slices(b"very secret key.", iv).unwrap();
mac.update(b"input message");

// `result` has type `Output` which is a thin wrapper around array of
// bytes for providing constant time equality check
let result = mac.finalize();
// To get underlying array use the `into_bytes` method, but be careful,
// since incorrect use of the tag value may permit timing attacks which
// defeat the security provided by the `Output` wrapper
let tag_bytes = result.into_bytes();
```

To verify the message:

```rust
use gmac::{KeyIvInit, Gmac, Gmac128, Mac};
use rand::rngs::SysRng;

# let iv = b"000000000000";

let mut mac = Gmac128::new_from_slices(b"very secret key.", iv).unwrap();

mac.update(b"input message");

# let tag_bytes = mac.clone().finalize().into_bytes();
// `verify` will return `Ok(())` if tag is correct, `Err(MacError)` otherwise
mac.verify(&tag_bytes).unwrap();
```

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/gmac.svg?logo=rust
[crate-link]: https://crates.io/crates/gmac
[docs-image]: https://docs.rs/gmac/badge.svg
[docs-link]: https://docs.rs/gmac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/actions/workflows/gmac.yml/badge.svg
[build-link]: https://github.com/RustCrypto/MACs/actions/workflows/gmac.yml

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[GMAC]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[`aes`]: https://docs.rs/aes
[SP 800-38D]: https://doi.org/10.6028/NIST.SP.800-38D