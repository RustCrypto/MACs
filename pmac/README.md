# RustCrypto: PMAC

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Generic implementation of [Parallelizable Message Authentication Code (PMAC)][1].

## Examples
We will use AES-128 block cipher from the [`aes`](https://docs.rs/aes) crate.

To get authentication code:

```rust
use aes::Aes128;
use pmac::{digest::KeyInit, Pmac, Mac};

// Create `Mac` trait implementation, namely PMAC-AES128
let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();
mac.update(b"input message");

// `result` has type `Output` which is a thin wrapper around array of
// bytes for providing constant time equality check
let result = mac.finalize();
// To get underlying array use `into_bytes` method, but be careful, since
// incorrect use of the tag value may permit timing attacks which defeat
// the security provided by the `Output` wrapper
let tag_bytes = result.into_bytes();
```

To verify the message:

```rust
# use aes::Aes128;
# use pmac::{digest::KeyInit, Pmac, Mac};
let mut mac = Pmac::<Aes128>::new_from_slice(b"very secret key.").unwrap();

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

[crate-image]: https://img.shields.io/crates/v/pmac.svg?logo=rust
[crate-link]: https://crates.io/crates/pmac
[docs-image]: https://docs.rs/pmac/badge.svg
[docs-link]: https://docs.rs/pmac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/workflows/pmac/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/MACs/actions?query=workflow%3Apmac

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/PMAC_(cryptography)
`aes`: https://docs.rs/aes
