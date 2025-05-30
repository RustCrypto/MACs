# RustCrypto: CBC-MAC

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Generic implementation of [Cipher Block Chaining Message Authentication Code (CBC-MAC)][CBC-MAC].

**WARNING!** The algorithm has known weaknesses in case of variable-length
messages. See the linked Wikipedia article for more information.

## Examples

```rust
use cbc_mac::{digest::KeyInit, CbcMac, Mac};
use des::Des;
use hex_literal::hex;

// CBC-MAC with the DES block cipher is equivalent to DAA
type Daa = CbcMac<Des>;

// test from FIPS 113
let key = hex!("0123456789ABCDEF");
let mut mac = Daa::new_from_slice(&key).unwrap();
mac.update(b"7654321 Now is the time for ");
let correct = hex!("F1D30F6849312CA4");
mac.verify_slice(&correct).unwrap();
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

[crate-image]: https://img.shields.io/crates/v/cbc-mac.svg?logo=rust
[crate-link]: https://crates.io/crates/cbc-mac
[docs-image]: https://docs.rs/cbc-mac/badge.svg
[docs-link]: https://docs.rs/cbc-mac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/actions/workflows/cbc-mac.yml/badge.svg
[build-link]: https://github.com/RustCrypto/MACs/actions/workflows/cbc-mac.yml

[//]: # (general links)

[CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC
