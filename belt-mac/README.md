# RustCrypto: belt-mac

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of [`belt-mac`].

# Example
```rust
use belt_mac::{digest::KeyInit, BeltMac, Mac};
use hex_literal::hex;

let key = [0x42; 32];
let msg = b"input message";
let expected_tag = hex!("9f5c9623b4eff8802195e81bcd841959");

// To get the authentication code:
let mut mac: BeltMac = BeltMac::new_from_slice(&key).unwrap();
mac.update(msg);
let tag = mac.finalize();
let tag_bytes = tag.into_bytes();
assert_eq!(&tag_bytes[..], &expected_tag[..]);

// To verify the message:
let mut mac: BeltMac = BeltMac::new_from_slice(&key).unwrap();
mac.update(b"input message");
mac.verify(&tag_bytes).unwrap();
```

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/belt-mac.svg?logo=rust
[crate-link]: https://crates.io/crates/belt-mac
[docs-image]: https://docs.rs/belt-mac/badge.svg
[docs-link]: https://docs.rs/belt-mac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/workflows/belt-mac/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/MACs/actions?query=workflow%3Abelt-mac

[//]: # (general links)

[belt-mac]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
