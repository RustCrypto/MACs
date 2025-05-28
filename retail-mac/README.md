# RustCrypto: Retail MAC

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Retail Message Authentication Code][Retail MAC],
also known as ISO/IEC 9797-1 MAC algorithm 3.

**WARNING!** The algorithm has known weaknesses in case of variable-length
messages. See the Wikipedia article for [CBC-MAC] for more information.

## Examples

```rust
use retail_mac::{digest::KeyInit, RetailMac, Mac};
use des::Des;
use hex_literal::hex;

type RetailMacDes = RetailMac<Des>;

// test from ISO/IEC 9797-1:2011 section B.4
// K and K' are concatenated:
let key = hex!("0123456789ABCDEFFEDCBA9876543210");

let mut mac = RetailMacDes::new_from_slice(&key).unwrap();
mac.update(b"Now is the time for all ");
let correct = hex!("A1C72E74EA3FA9B6");
mac.verify_slice(&correct).unwrap();

let mut mac2 = RetailMacDes::new_from_slice(&key).unwrap();
mac2.update(b"Now is the time for it");
let correct2 = hex!("2E2B1428CC78254F");
mac2.verify_slice(&correct2).unwrap();
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

[crate-image]: https://img.shields.io/crates/v/retail-mac.svg?logo=rust
[crate-link]: https://crates.io/crates/retail-mac
[docs-image]: https://docs.rs/retail-mac/badge.svg
[docs-link]: https://docs.rs/retail-mac/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260044-MACs
[build-image]: https://github.com/RustCrypto/MACs/actions/workflows/retail-mac.yml/badge.svg
[build-link]: https://github.com/RustCrypto/MACs/actions/workflows/retail-mac.yml

[//]: # (general links)

[Retail MAC]: https://en.wikipedia.org/wiki/ISO/IEC_9797-1#MAC_algorithm_3
[CBC-MAC]: https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages
